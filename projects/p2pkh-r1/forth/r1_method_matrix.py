"""Explore ordered R1 methods against fixed Forth and payment inputs."""

from dataclasses import dataclass, replace
from functools import cache, partial
from hashlib import sha256
from pathlib import Path
import platform

from compile_r1 import (BASELINE_DEPENDENCIES, BASELINE_SOURCE_SHA256, ENTRY_SOURCES, PAYMENT_ENTRY, compile_source,
                        dependencies, payment_window_boundaries)
from fourthgraph import PROJECT_VERSION
from fourthgraph.benchmark import method_matrix
from fourthgraph.benchmark.experiment import digest as digest_report
from fourthgraph.benchmark.method_matrix import IneligibleMethod, Method, explore_orders, explore_pairs
from fourthgraph.benchmark.cases import native_coin, synthetic_parent
from fourthgraph.benchmark.validation import (
    ACTIVATION_HEIGHT, CONTEXT_PIN, SPEND_HEIGHT, UTXO_HEIGHT, chain_metadata, stack_profile,
)
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.workflow.protocol import FLAG
from msm_compiler import OWNER, R1MSMCompiler
from msm_lowering import Strategy, clear_window_table, reconstruction, verify_window, window_program
from replay_r1 import FIXTURE, FIXTURE_PATH, MODES, signer, spend


SCHEMA = "4thgraph.r1-method-matrix/1"
SEARCH_SCHEMA = "4thgraph.r1-method-search/1"
METHODS = {
    "joint-window": ("window schedule and G/Q tables", "no fixed-G specialization"),
    "affine-g": ("G table call and point-add kernel", "separate G table and proof for nonzero digits"),
    "compact-g": ("G table representation, lookup and cleanup", "affine G specialization"),
    "ifdup": ("zero-digit guard feeding the affine call", "affine G specialization"),
    "point-add-stack-search": ("point-add kernels visible at this step", "typed point-add formulas"),
}
SEARCH_METHODS = {
    **METHODS,
    "widen-g-window": ("fixed G digit extraction, table and call schedule", "separate G table with sufficient slots"),
    "pack-prefix-repeat": ("OTDA reconstruction of repeated Script fragments", "a smaller constructor"),
    "narrow-q-window": ("runtime Q digit extraction, table and call schedule", "a separate Q table"),
    "pack-stack-repeat": ("OTDA repetition of Script fragments on the main stack", "a smaller constructor"),
    "pack-adjacent-kernels": ("OTDA copies of consecutive identical kernels", "a smaller constructor"),
}
PACKING_OPTIONS = {
    "pack-prefix-repeat": "prefix_repeat",
    "pack-stack-repeat": "stack_repeat",
    "pack-adjacent-kernels": "adjacent_kernels",
}
TERMINAL = ("rewrite", "share", "stack", "search")
STALE_ERROR = "Error evaluating the script `Top of stack is false`"


@dataclass(frozen=True)
class State:
    strategy: Strategy
    projective: bytes
    affine: bytes | None = None
    packing: frozenset[str] = frozenset()


def digest(code):
    return sha256(code).hexdigest()


def apply(method, state, *, backend, scheduled, constructor_for):
    strategy = state.strategy
    if method == "joint-window":
        if strategy.affine_g:
            raise IneligibleMethod("joint entries use Q and have no uniform finite Z=1 proof")
        return replace(state, strategy=backend.plan("joint-2").strategy)
    if method == "affine-g":
        if strategy.joint:
            raise IneligibleMethod("joint entries use Q and have no uniform finite Z=1 proof")
        if strategy.affine_g:
            return state
        return replace(state, strategy=replace(strategy, affine_g=True), affine=backend.affine[0])
    if method == "compact-g":
        if not strategy.affine_g:
            raise IneligibleMethod("compact G lookup needs the separate affine G table")
        return replace(state, strategy=replace(strategy, compact_g=True))
    if method == "ifdup":
        if not strategy.affine_g:
            raise IneligibleMethod("the zero-digit skip guard needs the affine G call")
        return replace(state, strategy=replace(strategy, affine_guard_ifdup=True))
    if method == "widen-g-window":
        if strategy.joint:
            raise IneligibleMethod("the joint window cannot widen G independently of Q")
        wider = replace(strategy, width=6, q_width=strategy.q_width or strategy.width)
        try:
            backend.plan(wider.name)
        except ValueError as error:
            raise IneligibleMethod(str(error)) from error
        return replace(state, strategy=wider)
    if method == "narrow-q-window":
        if strategy.joint:
            raise IneligibleMethod("the joint window cannot narrow Q independently of G")
        narrower = replace(strategy, q_width=3)
        try:
            backend.plan(narrower.name)
        except ValueError as error:
            raise IneligibleMethod(str(error)) from error
        return replace(state, strategy=narrower)
    if method in PACKING_OPTIONS:
        if method in state.packing:
            return state
        candidate = replace(state, packing=state.packing | {method})
        if len(constructor_for(candidate)) >= len(constructor_for(state)):
            raise IneligibleMethod("this packing option does not shorten the current constructor")
        return candidate
    if method != "point-add-stack-search":
        raise ValueError(f"unknown R1 method {method!r}")
    return replace(state, projective=scheduled["projective"],
                   affine=scheduled["affine"] if state.affine is not None else None)


def info(state):
    return {"window": state.strategy.name, "packing": sorted(state.packing),
            "projective_kernel": {"bytes": len(state.projective), "sha256": digest(state.projective)},
            "affine_kernel": None if state.affine is None else
                {"bytes": len(state.affine), "sha256": digest(state.affine)}}


def verify(tx, parents):
    validate_at_heights(tx, parents, spend_height=SPEND_HEIGHT, activation_height=ACTIVATION_HEIGHT,
                        utxo_heights=(UTXO_HEIGHT,) * len(tx.inputs))


def replay(lock, pattern):
    owners = tuple(map(signer, FIXTURE["test_owner_scalars"]))
    recipients = tuple(map(signer, FIXTURE["test_recipient_scalars"]))
    value = FIXTURE["funding_satoshis_per_output"]
    version = FIXTURE["transaction_version"]
    coin = native_coin("r1-method-matrix/funder", value * len(owners) + 10_000, p2pk=True)
    root = synthetic_parent("r1-method-matrix/root", coin)
    deposit = Transaction((Input(root.txid_wire(), 0),),
                          tuple(Output(value, lock.lock(owner)) for _, _, owner in owners), version)
    deposit = coin.unlock(deposit, 0, root, FLAG, None)
    verify(deposit, (root,))
    parents = (deposit,) * len(owners)
    rows = {}
    recipient_locks = [lock.lock(owner) for _, _, owner in recipients]
    for mode, flag in MODES.items():
        tx = spend(deposit, recipient_locks, pattern, owners, flag)
        verify(tx, parents)
        stale = replace(tx, locktime=1)
        try:
            verify(stale, parents)
        except ValueError as exc:
            if str(exc) != STALE_ERROR:
                raise
        else:
            raise AssertionError("stale witness unexpectedly passed")
        stack = [stack_profile(deposit.outputs[txin.vout].script, txin.script) for txin in tx.inputs]
        if any("unavailable" in row for row in stack):
            raise ValueError("stack observation failed")
        rows[mode] = {
            "funding_txid": deposit.txid(), "spend_txid": tx.txid(), "stale_txid": stale.txid(),
            "accepted": True, "stale_rejection": STALE_ERROR,
            "funding_bytes": len(deposit.serialize()), "spend_bytes": len(tx.serialize()),
            "total_bytes": len(deposit.serialize()) + len(tx.serialize()),
            "max_main_items": max(row["main_items"] for row in stack),
            "max_alt_items": max(row["alt_items"] for row in stack),
            "max_stack_payload_bytes": max(row["combined_payload_bytes"] for row in stack),
        }
    return rows


def run_experiment(*, search_budget=None):
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("expected pinned chain-gang")
    source_path = ENTRY_SOURCES[PAYMENT_ENTRY]
    source = source_path.read_bytes()
    optimized = compile_source(source, OWNER, optimize=True, source_path=source_path)
    backend = R1MSMCompiler()
    imports = dependencies(optimized)
    if digest(source) != BASELINE_SOURCE_SHA256 or imports != BASELINE_DEPENDENCIES:
        raise ValueError("R1 method exploration requires the verified baseline and import digests")
    if backend.source_identity["dependencies"] != imports:
        raise ValueError("window backend imports differ from the baseline")
    prologue, epilogue = payment_window_boundaries(optimized)
    prefix, before = prologue.split(OWNER)
    full, double = backend.kernels
    formula = optimized.formula_ir["r1-add-points"]
    scheduled = {"projective": formula.lower(passes=TERMINAL)[0],
                 "affine": formula.bind_input(5, 1).lower(passes=TERMINAL)[0]}
    start = State(backend.plan("split-5x4").strategy, full)
    receipts = {}

    @cache
    def program_for(strategy, projective, affine):
        return window_program(backend.plan(strategy.name), projective, double, affine=affine)

    @cache
    def verify_curve(strategy, projective, affine):
        return verify_window(program_for(strategy, projective, affine), 12)

    @cache
    def constructor_for(state):
        program = program_for(state.strategy, state.projective, state.affine)
        after = clear_window_table(program.table_slots) + epilogue
        options = {PACKING_OPTIONS[method]: True for method in state.packing}
        return reconstruction(prefix, before, program.pieces, after, program.kernels, **options)

    @cache
    def build(state):
        try:
            program = program_for(state.strategy, state.projective, state.affine)
            after = clear_window_table(program.table_slots) + epilogue
            suffix = before + program.emit() + after
            lock = replace(backend.reference, script=prefix + bytes(len(OWNER)) + suffix, owner_start=len(prefix))
            compressed = constructor_for(state)
            if evaluate(compressed) != ([prefix, suffix], []):
                raise ValueError("OTDA reconstructed different lock bytes")
            pattern = Reconstruction(compressed, (prefix, suffix), (len(OWNER),))
        except ValueError as error:
            return {"status": "compile_failed", "diagnostic": str(error)}

        lock_hash = digest(lock.script)
        otda_hash = digest(compressed)
        key = digest(bytes.fromhex(lock_hash + otda_hash))
        if key not in receipts:
            compiled = {
                "status": "passed", "lock_bytes": len(lock.script), "lock_sha256": lock_hash,
                "otda_program_bytes": len(compressed), "otda_program_sha256": otda_hash,
                "table_slots": program.table_slots, "sections_bytes": program.sections,
            }
            try:
                vectors = verify_curve(state.strategy, state.projective, state.affine)
                tested = {"status": "passed", "point_vectors": vectors, "modes": replay(lock, pattern)}
            except (ValueError, RuntimeError, AssertionError) as error:
                tested = {"status": "failed", "diagnostic": str(error)}
            receipts[key] = {"compile": compiled, "test": tested}
        status = "verified" if receipts[key]["test"]["status"] == "passed" else "test_failed"
        return {"status": status, "artifact": key}

    registry = METHODS if search_budget is None else SEARCH_METHODS
    methods = {
        name: Method(region, requires, partial(apply, name, backend=backend, scheduled=scheduled, constructor_for=constructor_for))
        for name, (region, requires) in registry.items()
    }
    if search_budget is None:
        seeds = {"from_split": start, "from_affine": methods["affine-g"].apply(start)}
        matrices = explore_pairs(seeds, methods, describe=info, evaluate=build)
        rows = [(seed, row) for seed, matrix in matrices.items() for row in (matrix["baseline"], *matrix["cells"])]
        exploration = {"schema": SCHEMA, "matrices": matrices}
    else:
        search = explore_orders(start, methods, describe=info, evaluate=build, **search_budget)
        rows = [("from_split", row) for row in search["states"]]
        exploration = {"schema": SEARCH_SCHEMA, "search": search}

    plans = {}
    for seed, row in rows:
        if row["status"] == "verified":
            plans.setdefault(row["artifact"], {"seed": seed, "order": row["order"], "artifact": row["artifact"]})
    rankings = {
        mode: sorted(plans.values(), key=lambda plan: receipts[plan["artifact"]]["test"]["modes"][mode]["total_bytes"])
        for mode in MODES
    }
    package = Path(method_matrix.__file__).resolve().parents[1]
    project = Path(__file__).resolve().parents[1]
    tools = {f"fourthgraph/{path.relative_to(package)}": digest(path.read_bytes())
             for path in sorted(package.rglob("*.py"))}
    for directory in ("forth", "reference"):
        tools.update({f"p2pkh-r1/{path.relative_to(project)}": digest(path.read_bytes())
                      for path in sorted((project / directory).glob("*.py"))})
    report = {
        **exploration, "compiler_version": PROJECT_VERSION, "python": platform.python_version(),
        "source_sha256": digest(source), "imports": imports, "target_terminal_passes": TERMINAL,
        "fixture": {"sha256": digest(FIXTURE_PATH.read_bytes()), "shape": [2, 2],
                    "transaction_version": FIXTURE["transaction_version"], "engine": engine,
                    "spend_height": SPEND_HEIGHT, "activation_height": ACTIVATION_HEIGHT,
                    "utxo_height": UTXO_HEIGHT},
        "tool_sha256": digest_report(tools),
        "methods": {name: {"region": method.region, "requires": method.requires} for name, method in methods.items()},
        "artifacts": receipts, "rankings": rankings,
    }
    failures = {"compile_failed", "test_failed"}
    status = "failed" if any(row["status"] in failures for _, row in rows) else "passed"
    report["status"] = status
    return {**report, "run_id": digest_report(report)}

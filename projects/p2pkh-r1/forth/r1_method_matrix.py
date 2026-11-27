"""Explore ordered R1 methods against fixed Forth and payment inputs."""

from dataclasses import replace
from functools import cache
from pathlib import Path
import platform

from compile_r1 import ENTRY_SOURCES, PAYMENT_ENTRY
from fourthgraph import PROJECT_VERSION
from fourthgraph.benchmark import method_matrix
from fourthgraph.benchmark.experiment import digest as digest_report
from fourthgraph.benchmark.method_matrix import explore_pairs
from fourthgraph.benchmark.cases import native_coin, synthetic_parent
from fourthgraph.benchmark.validation import (
    ACTIVATION_HEIGHT, CONTEXT_PIN, SPEND_HEIGHT, UTXO_HEIGHT, chain_metadata, stack_profile,
)
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.workflow.protocol import FLAG
from msm_lowering import verify_window
from r1_optimizer import R1Optimizer, State, TERMINAL, digest, info
from replay_r1 import FIXTURE, FIXTURE_PATH, MODES, signer, spend


SCHEMA = "4thgraph.r1-method-matrix/1"
SEARCH_SCHEMA = "4thgraph.r1-method-search/1"
STALE_ERROR = "Error evaluating the script `Top of stack is false`"


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
    optimizer = R1Optimizer(source, source_path)
    receipts = {}

    @cache
    def verify_curve(strategy, projective, affine):
        return verify_window(optimizer.program_for(State(strategy, projective, affine)), 12)

    @cache
    def build(state):
        try:
            linked = optimizer.link(state)
        except ValueError as error:
            return {"status": "compile_failed", "diagnostic": str(error)}

        metrics = linked.metrics()
        key = digest(bytes.fromhex(metrics["lock_sha256"] + metrics["otda_program_sha256"]))
        if key not in receipts:
            compiled = {"status": "passed", **metrics}
            try:
                vectors = verify_curve(state.strategy, state.projective, state.affine)
                tested = {"status": "passed", "point_vectors": vectors, "modes": replay(linked.lock, linked.pattern)}
            except (ValueError, RuntimeError, AssertionError) as error:
                tested = {"status": "failed", "diagnostic": str(error)}
            receipts[key] = {"compile": compiled, "test": tested}
        status = "verified" if receipts[key]["test"]["status"] == "passed" else "test_failed"
        return {"status": status, "artifact": key}

    methods = optimizer.methods(pairs=search_budget is None)
    start = optimizer.start
    if search_budget is None:
        seeds = {"from_split": start, "from_affine": methods["affine-g"].apply(start)}
        matrices = explore_pairs(seeds, methods, describe=info, evaluate=build)
        rows = [(seed, row) for seed, matrix in matrices.items() for row in (matrix["baseline"], *matrix["cells"])]
        exploration = {"schema": SCHEMA, "matrices": matrices}
    else:
        search = optimizer.search(methods=methods, evaluate=build, **search_budget)
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
        "source_sha256": digest(source), "imports": optimizer.imports, "target_terminal_passes": TERMINAL,
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

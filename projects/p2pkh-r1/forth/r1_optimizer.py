"""Ordered lowering and target-cost selection for the verified R1 Forth entry."""

from dataclasses import dataclass, replace
from functools import cache, partial
from hashlib import sha256
from importlib.resources import files

from compile_r1 import (AUTO_OBJECTIVES, BASELINE_DEPENDENCIES, BASELINE_SOURCE_SHA256, PAYMENT_ENTRY, compile_source,
                        dependencies, payment_window_boundaries)
from fixed_templates import CompiledTemplate
from fourthgraph import PROJECT_VERSION
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.otda_reconstruction import Reconstruction
from fourthgraph.bsv.transaction import compact
from fourthgraph.compiler.method_search import IneligibleMethod, Method, explore_orders, replay_order
from msm_compiler import OWNER, R1MSMCompiler
from msm_lowering import Program, Strategy, clear_window_table, reconstruction, share_reconstruction_fragments, window_program


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
FRAGMENT_SHARING = "share-otda-fragments"
TERMINAL = ("rewrite", "share", "stack", "search")


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
    if method in PACKING_OPTIONS or method == FRAGMENT_SHARING:
        if method in state.packing:
            return state
        candidate = replace(state, packing=state.packing | {method})
        if len(constructor_for(candidate)) >= len(constructor_for(state)):
            raise IneligibleMethod("this packing option does not shorten the current constructor")
        return candidate
    if method != "point-add-stack-search":
        raise ValueError(f"unknown R1 method {method!r}")
    return replace(state, projective=scheduled(False),
                   affine=scheduled(True) if state.affine is not None else None)


def info(state):
    return {"window": state.strategy.name, "packing": sorted(state.packing),
            "projective_kernel": {"bytes": len(state.projective), "sha256": digest(state.projective)},
            "affine_kernel": None if state.affine is None else
                {"bytes": len(state.affine), "sha256": digest(state.affine)}}


DEFAULT_COMPILER_STATES = 160
PLAN_SCHEMA = "4thgraph.r1-optimization-plan/2"


class UnrecognizedBaseline(ValueError):
    """The call-region proof is unavailable for this Forth snapshot."""


@dataclass(frozen=True)
class LinkedR1:
    program: Program
    lock: CompiledTemplate
    pattern: Reconstruction

    def metrics(self):
        return {
            "lock_bytes": len(self.lock.script), "lock_sha256": digest(self.lock.script),
            "otda_program_bytes": len(self.pattern.program), "otda_program_sha256": digest(self.pattern.program),
            "table_slots": self.program.table_slots, "sections_bytes": self.program.sections,
        }


class R1Optimizer:
    def __init__(self, source, source_path):
        if digest(source) != BASELINE_SOURCE_SHA256:
            raise UnrecognizedBaseline("R1 source digest differs from the verified baseline")
        self.compiler = compile_source(source, OWNER, optimize=True, source_path=source_path)
        self.imports = dependencies(self.compiler)
        if self.imports != BASELINE_DEPENDENCIES:
            raise UnrecognizedBaseline("R1 import digests differ from the verified baseline")
        self.backend = R1MSMCompiler()
        if self.backend.source_identity["dependencies"] != self.imports:
            raise ValueError("R1 window backend imports differ from the baseline")
        prologue, self.epilogue = payment_window_boundaries(self.compiler)
        self.prefix, self.before = prologue.split(OWNER)
        full, self.double = self.backend.kernels
        formula = self.compiler.formula_ir["r1-add-points"]

        @cache
        def schedule(affine):
            kernel = formula.bind_input(5, 1) if affine else formula
            return kernel.lower(passes=TERMINAL)[0]

        self.schedule = schedule
        self.start = State(self.backend.plan("split-5x4").strategy, full)
        self._programs = {}
        self._constructors = {}
        self._linked = {}

    def methods(self, *, pairs=False, fragment_sharing=False):
        registry = METHODS if pairs else SEARCH_METHODS
        if fragment_sharing:
            registry = {**registry, FRAGMENT_SHARING: (
                "OTDA copies of repeated byte strings", "a smaller byte-exact constructor",
            )}
        return {
            name: Method(region, requires, partial(apply, name, backend=self.backend, scheduled=self.schedule,
                                                  constructor_for=self.constructor_for))
            for name, (region, requires) in registry.items()
        }

    def program_for(self, state):
        key = (state.strategy, state.projective, state.affine)
        if key not in self._programs:
            self._programs[key] = window_program(self.backend.plan(state.strategy.name), state.projective,
                                                 self.double, affine=state.affine)
        return self._programs[key]

    def constructor_for(self, state):
        if state not in self._constructors:
            program = self.program_for(state)
            after = clear_window_table(program.table_slots) + self.epilogue
            options = {PACKING_OPTIONS[method]: True for method in state.packing if method in PACKING_OPTIONS}
            pack = share_reconstruction_fragments if FRAGMENT_SHARING in state.packing else reconstruction
            self._constructors[state] = pack(
                self.prefix, self.before, program.pieces, after, program.kernels, **options,
            )
        return self._constructors[state]

    def link(self, state):
        if state not in self._linked:
            program = self.program_for(state)
            after = clear_window_table(program.table_slots) + self.epilogue
            suffix = self.before + program.emit() + after
            lock = CompiledTemplate(self.prefix + bytes(len(OWNER)) + suffix, len(self.prefix))
            compressed = self.constructor_for(state)
            if evaluate(compressed) != ([self.prefix, suffix], []):
                raise ValueError("OTDA reconstructed different lock bytes")
            self._linked[state] = LinkedR1(program, lock, lock.reconstruction(compressed))
        return self._linked[state]

    def search(self, *, methods=None, evaluate, **budget):
        if methods is None:
            methods = self.methods()
        return explore_orders(self.start, methods, describe=info, evaluate=evaluate, **budget)


def selection_cost(linked, objective):
    lock_bytes = len(linked.lock.script)
    if objective == "lock":
        return lock_bytes
    # The comparison profile has two R1 outputs in funding and two in spending.
    # Only candidate-dependent size terms are counted. It omits signatures and
    # witness framing, which the independent fixture measures on the final bytes.
    lock_terms = 4 * (lock_bytes + len(compact(lock_bytes)))
    return lock_terms + (2 * len(linked.pattern.program) if objective.startswith("otda-") else 0)


def plan_snapshot(optimizer):
    # Different compiler revisions can share PROJECT_VERSION. Identify the
    # compiler's packaged sources by content, independent of install location.
    sources = sorted((path for path in files("fourthgraph.compiler").iterdir()
                      if path.is_file() and path.name.endswith((".py", ".fth"))), key=lambda path: path.name)
    identity = sha256()
    for path in sources:
        identity.update(path.name.encode() + b"\0" + sha256(path.read_bytes()).digest())
    return {"compiler_version": PROJECT_VERSION, "entry": PAYMENT_ENTRY,
            "compiler_sha256": identity.hexdigest(),
            "source_sha256": BASELINE_SOURCE_SHA256, "window_backend": optimizer.backend.source_identity}


def plan_artifacts(linked):
    return {"lock_template_sha256": digest(linked.lock.script),
            "otda_program_sha256": digest(linked.pattern.program)}


def constructor_report(linked):
    program = linked.pattern.program
    return {"program_hex": program.hex(), "bytes": len(program), "sha256": digest(program),
            "owner_offset": linked.lock.owner_start, "owner_bytes": len(OWNER)}


def replay_plan(source, owner, plan, *, source_path):
    fields = {"schema", "snapshot", "objective", "order", "expected"}
    if isinstance(plan, dict) and plan.get("schema") == "4thgraph.r1-optimization-plan/1":
        raise ValueError("R1 v1 plans require their original compiler checkout")
    if (not isinstance(plan, dict) or plan.keys() != fields
            or plan["schema"] != PLAN_SCHEMA or plan["objective"] not in AUTO_OBJECTIVES):
        raise ValueError("invalid R1 optimization plan")
    if len(owner) != len(OWNER):
        raise ValueError("expected a 20-byte owner hash")
    optimizer = R1Optimizer(source, source_path)
    if plan["snapshot"] != plan_snapshot(optimizer):
        raise ValueError("R1 optimization plan snapshot differs from the compiler, source, or dependencies")
    linked = optimizer.link(replay_order(optimizer.start, optimizer.methods(fragment_sharing=True), plan["order"]))
    if plan["expected"] != plan_artifacts(linked):
        raise ValueError("R1 optimization plan emitted different lock or reconstruction bytes")
    return optimizer.compiler, linked.lock.lock(owner), constructor_report(linked)


def compile_ordered(source, owner, *, source_path, objective="lock", **budget):
    if objective not in AUTO_OBJECTIVES:
        raise ValueError(f"unknown R1 optimization objective {objective!r}")
    if len(owner) != len(OWNER):
        raise ValueError("expected a 20-byte owner hash")
    optimizer = R1Optimizer(source, source_path)
    candidates = []

    def score(state):
        result = optimizer.link(state)
        candidates.append(result)
        return {**result.metrics(), "score_bytes": selection_cost(result, objective)}

    methods = optimizer.methods()
    search = optimizer.search(methods=methods, evaluate=score, **budget)
    winner = min(search["states"], key=lambda row: (row["score_bytes"], row["lock_bytes"], len(row["order"])))
    linked = candidates[winner["id"]]
    offset = len(optimizer.prefix) + len(OWNER) + len(optimizer.before)
    end = len(linked.lock.script) - len(optimizer.epilogue)
    report = {
        "objective": objective,
        "score_model": "lock-script-bytes" if objective == "lock" else "two-input-two-output-variable-bytes",
        "validation_scope": "byte-exact-lock-reconstruction",
        "score_bytes": winner["score_bytes"],
        "window_backend": optimizer.backend.source_identity,
        "methods": {name: {"region": method.region, "requires": method.requires} for name, method in methods.items()},
        "linked_region": {"offset": offset, "bytes": end - offset,
                          "sha256": digest(linked.lock.script[offset:end])},
        "selected": winner["state"]["window"], "selected_order": winner["order"],
        "selected_state": winner["id"], "search": search,
        "plan": {"schema": PLAN_SCHEMA, "snapshot": plan_snapshot(optimizer), "objective": objective,
                 "order": winner["order"], "expected": plan_artifacts(linked)},
        "otda_reconstruction": constructor_report(linked),
    }
    return optimizer.compiler, linked.lock.lock(owner), report

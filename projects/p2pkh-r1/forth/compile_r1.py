"""Build a complete R1 lock by evaluating Forth Script-construction words."""

import argparse
from dataclasses import replace
from itertools import islice
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.compiler.method_search import MAX_ORDER_DEPTH, MAX_ORDER_STATES
from fourthgraph.compiler.script_builder import ScriptBuilder, build_word

VERSION = "0.4.0"
BASELINE_VERSION = "0.2.0"
SOURCE = Path(__file__).with_name("r1.fth")
PAYMENT_ENTRY = "r1-baseline-lock"
COUNTER_ENTRY = "r1-baseline-counter"
PELS_ENTRY = "r1-pels-lock"
STATEFUL_ENTRIES = {COUNTER_ENTRY, PELS_ENTRY}
# The first call-region rewrite is limited to the audited baseline and imports.
# The table compiler relies on this verifier's point check and scalar reduction.
BASELINE_SOURCE_SHA256 = "877f30ef15d05758d30aefc0d2666dc338d118d802492e795cb0400b44f3a3c6"
BASELINE_DEPENDENCIES = {
    "r1.fth": "c79cf9ba9a20d9a9c01274ae6676e2ae51b0de2de365266ebe3467c706ba13e3",
    "std/bsv": "92f4510c9d3e8e0371d9b41d08f9f7e639324c9795e6d0a1c3f9779e9179b404",
}
WINDOW_PLANS = ("split-4", "joint-2", "split-5x4-affine-g", "split-5x4-affine-g-ifdup")
MAX_AUTO_ROUNDS = 6
MAX_AUTO_CANDIDATES = 32
AUTO_BATCH = 8
AUTO_OBJECTIVES = ("lock", "bip143-all", "otda-all", "otda-single")
ENTRY_SOURCES = {
    "r1-lock": SOURCE,
    PAYMENT_ENTRY: SOURCE.with_name("r1-baseline.fth"),
    COUNTER_ENTRY: SOURCE.with_name("r1-baseline-counter.fth"),
    PELS_ENTRY: SOURCE.with_name("r1-pels-lock.fth"),
}


def compile_source(source, owner, *, optimize=False, source_path=SOURCE):
    if len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    return ScriptBuilder(source.decode(), source_path=source_path, optimize=optimize,
                         vocabulary={"bsv-owner": build_word("", "bytes", lambda: owner)})


def previous_build(owner, *, optimize):
    return ScriptBuilder("REQUIRE stdlib/wallet/r1.fth", vocabulary={
        "bsv-owner": build_word("", "bytes", lambda: owner),
        "bsv-optimize?": build_word("", "cell", lambda: -int(optimize)),
    })


def emit_lock(compiler, entry, counter_state=None):
    if entry in STATEFUL_ENTRIES:
        if type(counter_state) is not int or not 0 <= counter_state < 2**32:
            raise ValueError("the counter entry requires an unsigned 32-bit --counter-state")
        return compiler.emit(entry, b"", counter_state.to_bytes(5, "little"))
    if counter_state is not None:
        raise ValueError("--counter-state is only supported by the counter entry")
    return compiler.emit(entry, b"")


def dependencies(compiler):
    return {item.name: item.sha256 for item in compiler.library_imports}


def neighboring_windows(strategy):
    if strategy.joint:
        for delta in (-1, 1):
            yield replace(strategy, width=strategy.width + delta)
        return

    g = strategy.width
    q = strategy.q_width or g
    for dg, dq in ((-1, 0), (1, 0), (0, -1), (0, 1), (-1, -1), (1, 1)):
        q_width = q + dq
        if strategy.q_width is None and g + dg == q_width:
            q_width = None
        yield replace(strategy, width=g + dg, q_width=q_width)
    if strategy.affine_g:
        yield replace(strategy, affine_guard_ifdup=not strategy.affine_guard_ifdup)
        yield replace(strategy, affine_g=False, affine_guard_ifdup=False)
    else:
        yield replace(strategy, affine_g=True)
        yield replace(strategy, affine_g=True, affine_guard_ifdup=True)


def next_window_plans(backend, tested, candidates):
    seen = set(tested)
    # Explore the best linked locks first. Ties keep the original build order.
    for name in sorted(tested, key=lambda name: len(candidates[name])):
        for strategy in neighboring_windows(tested[name].strategy):
            if strategy.name in seen:
                continue
            seen.add(strategy.name)
            try:
                plan = backend.plan(strategy.name)
            except ValueError:
                continue
            yield plan


def window_search(backend, before, after, candidates, rounds):
    from msm_lowering import clear_window_table

    fragments, tested, history = {}, {}, []
    plans = [backend.plan(name) for name in WINDOW_PLANS]
    seed_names = list(candidates)
    stop = "round_budget"
    for index in range(rounds):
        for plan in plans:
            program = backend.lower(plan)
            # The original result check expects only the projective result above p, 3b, r.
            fragment = program.emit() + clear_window_table(program.table_slots)
            name = plan.strategy.name
            tested[name] = plan
            candidates[name] = before + fragment + after
            fragments[name] = {"offset": len(before), "bytes": len(fragment),
                               "sha256": sha256(fragment).hexdigest()}
        winner = select_baseline_plan(candidates)
        history.append({"round": index + 1, "candidates": seed_names + [p.strategy.name for p in plans],
                        "best": winner, "best_lock_bytes": len(candidates[winner])})
        seed_names = []
        available = MAX_AUTO_CANDIDATES - len(candidates)
        if not available:
            stop = "candidate_budget"
            break
        if index + 1 < rounds:
            plans = list(islice(next_window_plans(backend, tested, candidates), min(AUTO_BATCH, available)))
            if not plans:
                stop = "exhausted"
                break
    return fragments, history, stop


def payment_window_boundaries(compiler):
    before = compiler.emit("r1-prepare-scalars", compiler.emit("r1-prepare-lock", b""))
    after = compiler.emit("r1-bind-transaction", compiler.emit("r1-baseline-check-x", b""))
    return before, after


def baseline_plans(source, owner, *, source_path=ENTRY_SOURCES[PAYMENT_ENTRY], rounds=1):
    if type(rounds) is not int or not 1 <= rounds <= MAX_AUTO_ROUNDS:
        raise ValueError(f"auto rounds must be an integer between 1 and {MAX_AUTO_ROUNDS}")
    raw = compile_source(source, owner, source_path=source_path)
    optimized = compile_source(source, owner, optimize=True, source_path=source_path)
    imports = dependencies(raw)
    if imports != dependencies(optimized):
        raise ValueError("R1 dependencies changed between the baseline and optimized builds")

    candidates = {"baseline": emit_lock(raw, PAYMENT_ENTRY),
                  "formula": emit_lock(optimized, PAYMENT_ENTRY)}
    region = {"status": "ineligible", "reason": "source or dependency digest differs"}
    if sha256(source).hexdigest() == BASELINE_SOURCE_SHA256 and imports == BASELINE_DEPENDENCIES:
        from msm_compiler import R1MSMCompiler

        backend = R1MSMCompiler()
        if backend.source_identity["dependencies"] != imports:
            raise ValueError("R1 window backend dependencies differ from the payment entry")
        # Keep the original prologue, result check and transaction binding.
        before, after = payment_window_boundaries(optimized)
        fragments, history, stop = window_search(backend, before, after, candidates, rounds)
        region = {"status": "matched", "backend": backend.source_identity, "fragments": fragments}
    else:
        winner = select_baseline_plan(candidates)
        history = [{"round": 1, "candidates": list(candidates), "best": winner,
                    "best_lock_bytes": len(candidates[winner])}]
        stop = "ineligible"
    search = {"requested_rounds": rounds, "candidate_limit": MAX_AUTO_CANDIDATES,
              "rounds": history, "stop": stop}
    return raw, optimized, candidates, {**region, "search": search}


def select_baseline_plan(candidates):
    # Iteration order is deterministic, with the references ahead of window plans.
    return min(candidates, key=lambda name: len(candidates[name]))


def compile_auto(source, owner, *, source_path=ENTRY_SOURCES[PAYMENT_ENTRY], rounds=None, objective="lock",
                 max_depth=None, max_states=None):
    if objective not in AUTO_OBJECTIVES:
        raise ValueError(f"unknown R1 optimization objective {objective!r}")
    if rounds is None:
        if sha256(source).hexdigest() == BASELINE_SOURCE_SHA256:
            from r1_optimizer import DEFAULT_COMPILER_STATES, UnrecognizedBaseline, compile_ordered

            try:
                return compile_ordered(source, owner, source_path=source_path, objective=objective,
                                       max_depth=MAX_ORDER_DEPTH if max_depth is None else max_depth,
                                       max_states=DEFAULT_COMPILER_STATES if max_states is None else max_states)
            except UnrecognizedBaseline:
                pass
        if objective.startswith("otda-"):
            raise ValueError("OTDA selection requires the verified R1 baseline and imports")
    elif objective != "lock" or max_depth is not None or max_states is not None:
        raise ValueError("explicit window rounds cannot be combined with ordered search options")

    raw, optimized, candidates, region = baseline_plans(source, owner, source_path=source_path,
                                                        rounds=1 if rounds is None else rounds)
    selected = select_baseline_plan(candidates)
    report = {
        "objective": "lock_script_bytes", "requested_objective": objective,
        "region": "r1-baseline-mul2", "window_region": region,
        "selected": selected, "candidates": {
            name: {"lock_bytes": len(code), "lock_sha256": sha256(code).hexdigest()}
            for name, code in candidates.items()
        },
    }
    return raw if selected == "baseline" else optimized, candidates[selected], report


def describe_pels_blocks(compiler, owner, state, lock):
    transition = compiler.emit("increment-and-pay-fee", b"")
    segments = (
        ("r1-pels-state", compiler.emit("r1-pels-state", b"", state.to_bytes(5, "little"))),
        ("pels-verify", compiler.emit("pels-verify", b"", transition)),
        ("r1-verify-owner", compiler.emit("r1-verify-owner", b"", owner)),
    )
    if b"".join(code for _, code in segments) != lock:
        raise ValueError("standalone blocks do not reproduce the emitted lock")
    offset = 0
    blocks = []
    for name, code in segments:
        blocks.append({"word": name, "offset": offset, "bytes": len(code), "sha256": sha256(code).hexdigest()})
        offset += len(code)
    return blocks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--entry", choices=ENTRY_SOURCES, default="r1-lock")
    parser.add_argument("--counter-state", type=int, help="initial u32 state for a counter entry")
    parser.add_argument("--owner-hash160", type=bytes.fromhex, default=bytes(20))
    optimization = parser.add_mutually_exclusive_group()
    optimization.add_argument("--optimize", action="store_true")
    optimization.add_argument("--auto", action="store_true",
                              help="select and link an audited R1 lowering for the requested byte objective")
    parser.add_argument("--auto-target", choices=AUTO_OBJECTIVES,
                        help="byte objective for ordered --auto (default: lock)")
    parser.add_argument("--auto-depth", type=int, choices=range(1, MAX_ORDER_DEPTH + 1),
                        metavar=f"1..{MAX_ORDER_DEPTH}", help="ordered search depth")
    parser.add_argument("--auto-states", type=int, choices=range(1, MAX_ORDER_STATES + 1),
                        metavar=f"1..{MAX_ORDER_STATES}", help="ordered search state budget")
    parser.add_argument("--auto-rounds", type=int, choices=range(1, MAX_AUTO_ROUNDS + 1),
                        help="use the window-only search with this many rounds")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    ordered = (args.auto_target, args.auto_depth, args.auto_states)
    if not args.auto and (args.auto_rounds is not None or any(value is not None for value in ordered)):
        parser.error("search options require --auto")
    if args.auto_rounds is not None and any(value is not None for value in ordered):
        parser.error("--auto-rounds cannot be combined with ordered search options")
    source_path = args.source or ENTRY_SOURCES[args.entry]
    source = source_path.read_bytes()
    try:
        if args.auto:
            if args.entry != PAYMENT_ENTRY or args.counter_state is not None:
                raise ValueError("--auto requires the r1-baseline-lock payment entry")
            compiler, lock, report = compile_auto(source, args.owner_hash160, source_path=source_path,
                                                  rounds=args.auto_rounds, objective=args.auto_target or "lock",
                                                  max_depth=args.auto_depth, max_states=args.auto_states)
            constructor = report.pop("otda_reconstruction", None)
            blocks = {"optimization": report}
            if constructor is not None:
                blocks["otda_reconstruction"] = constructor
        else:
            compiler = compile_source(source, args.owner_hash160, optimize=args.optimize, source_path=source_path)
            lock = emit_lock(compiler, args.entry, args.counter_state)
            blocks = ({"blocks": describe_pels_blocks(compiler, args.owner_hash160, args.counter_state, lock)}
                      if args.entry == PELS_ENTRY else {})
    except ValueError as error:
        parser.error(str(error))
    identity = ({"experiment_version": VERSION, "baseline_version": BASELINE_VERSION, "lock_version": VERSION}
                if args.entry == "r1-lock" else {"entry": args.entry, "counter_state": args.counter_state,
                                                 "dependencies": dependencies(compiler)})
    print(json.dumps({
        **identity, **blocks, "formulas": compiler.formulas,
        "source_sha256": sha256(source).hexdigest(), "optimized": compiler.optimize,
        "lock_bytes": len(lock), "lock_sha256": sha256(lock).hexdigest(), "lock_hex": lock.hex(),
    }, indent=2))


if __name__ == "__main__":
    main()

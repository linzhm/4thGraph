"""Replay binary and 64-window Forth with the same compiler and Bitcoin transactions."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from compare import HERE, compile_candidate, compiled_template, measure, plans, replay, verifier
from compare_otda import replay as replay_constructor
from constructor_matrix import AUTO, cases as matrix_cases, replay as replay_matrix
from schnorr_script import output_reconstruction
from window_build import compile_window_candidate
from fourthgraph import PROJECT_VERSION
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.compiler.curve_lowering import compile_fixed_generator
from fourthgraph.compiler.curve_windows import CURVES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--matrix-only", action="store_true", help="replay the eight automatic transaction shapes")
    args = parser.parse_args()
    engine = chain_metadata()
    if not os.environ.get("REGTEST_URL") or engine["commit"] != CONTEXT_PIN or args.samples < 1:
        parser.error("use pinned chain-gang, positive --samples, and tools/verify_node.sh")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    plan_by_name = {plan.name: plan for plan in plans()}
    manual, offset = compiled_template(bytes(20))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.matrix_only:
        activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
        if activation < 3:
            parser.error("use REGTEST_CHRONICLE_HEIGHT=5 for the transaction matrix")
        _, lock, _, _ = compile_window_candidate(plan_by_name["compiler-auto"], linked=True)
        rows = [replay_matrix(node, case, activation, (lock, offset)) for case in matrix_cases() if AUTO in case.sources]
        report = {"compiler": PROJECT_VERSION, "chain_gang": engine, "bsv_node": node.version,
                  "chronicle_height": activation,
                  "automatic_lock_sha256": sha256(lock).hexdigest(), "rows": rows}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        return
    old = json.loads((HERE / "measurements.json").read_text())

    builds = {"manual-v0.17.0": (verifier(), manual)}
    binary, lock, _, _ = compile_candidate(plan_by_name["compiler-auto"])
    builds["binary-auto"] = binary, lock
    if sha256(lock).hexdigest() != old["candidates"]["compiler-auto"]["lock_sha256"]:
        raise ValueError("binary control differs from the frozen comparison")
    for label, plan in (("window-baseline", "source-baseline"), ("window-auto", "compiler-auto")):
        code, lock, _, _ = compile_window_candidate(plan_by_name[plan])
        builds[label] = code, lock
    code, lock, _, _ = compile_window_candidate(plan_by_name["compiler-auto"], linked=True)
    builds["window-linked-auto"] = code, lock

    rows, timing_inputs = {}, {}
    for name, (code, lock) in builds.items():
        receipt, timing = replay(node, code, lock, offset)
        timing_inputs[name] = timing
        pattern = output_reconstruction(lock, offset)
        constructors = replay_constructor(node, name, lock, offset, pattern, (2, 2))
        rows[name] = {
            "verifier_bytes": len(code), "verifier_sha256": sha256(code).hexdigest(),
            "lock_bytes": len(lock), "lock_sha256": sha256(lock).hexdigest(),
            "verification": receipt, "2x2_otda_all": constructors, "constructor_bytes": len(pattern.program),
        }
        print(name, len(lock), constructors["reconstructed"]["transaction_bytes"], flush=True)
    timing_names = ("manual-v0.17.0", "binary-auto", "window-auto", "window-linked-auto")
    fixed = {name: compile_fixed_generator(curve).candidates for name, curve in CURVES.items()}
    report = {"compiler": PROJECT_VERSION, "chain_gang": engine, "bsv_node": node.version, "samples": args.samples,
              "timings_ms": measure(node, {name: timing_inputs[name] for name in timing_names}, args.samples),
              "fixed_generator_lowering": fixed, "results": rows,
              "selected_automatic": min((name for name in timing_names if name != "manual-v0.17.0"),
                                        key=lambda name: rows[name]["lock_bytes"])}
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

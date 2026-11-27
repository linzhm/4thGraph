"""Replay binary and 64-window Forth with the same compiler and Bitcoin transactions."""
import argparse
from dataclasses import replace
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
from fourthgraph.compiler.curve_windows import CURVES, GLV_REFERENCE, GLV_SCALED, JOINT_STRATEGIES
from fourthgraph.compiler.lowering import DATAFLOW
from fourthgraph.compiler.script_builder import ScriptBuilder


def manual_window_sequence(library):
    return library.emit("bip340-first-window", b"") + 63 * library.emit("bip340-joint-window-step", b"")


def compare_scaled_regions(manual, automatic, joint_code):
    """Measure the regions around the identical first and repeated window scripts."""
    hand, hand_lock = manual
    auto, auto_lock = automatic
    library = ScriptBuilder("REQUIRE stdlib/bip340.fth")
    manual_setup = library.emit("bip340-joint-window-table", b"")
    loop = manual_window_sequence(library)
    if loop not in auto:
        return {"identical_window_script": False}
    manual_start, automatic_start = hand.index(loop), auto.index(loop)
    manual_setup_start, joint_start = hand.index(manual_setup), auto.index(joint_code)
    if manual_setup_start + len(manual_setup) != manual_start:
        raise ValueError("unexpected v0.17.0 table layout")

    def row(original, compiled):
        return {"manual_bytes": original, "automatic_bytes": compiled, "difference_bytes": compiled - original}

    return {
        "identical_window_script": True,
        "depth_and_challenge": row(manual_setup_start, joint_start),
        "joint_preparation": row(len(manual_setup), automatic_start - joint_start),
        "windows": row(len(loop), len(loop)),
        "cleanup_and_nonce_check": row(len(hand) - manual_start - len(loop), len(auto) - automatic_start - len(loop)),
        "owner_and_transaction_binding": row(len(hand_lock) - len(hand), len(auto_lock) - len(auto)),
        "payment_lock": row(len(hand_lock), len(auto_lock)),
    }


def compare_output_regions(builds, base):
    """The model adapters may move across the linked call, so use the loop as the boundary."""
    loop = manual_window_sequence(ScriptBuilder("REQUIRE stdlib/bip340.fth"))
    regions = {}
    for name in (base, base + "/fused", base + "/paired"):
        detached, _ = builds[name]
        offset = detached.find(loop)
        if offset < 0:
            regions[name] = {"identical_window_script": False}
        else:
            regions[name] = {"identical_window_script": True, "before_windows": offset, "windows": len(loop),
                             "after_windows": len(detached) - offset - len(loop)}
    return regions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--matrix-only", action="store_true", help="replay the eight automatic transaction shapes")
    parser.add_argument("--joint-lowerings", action="store_true", help="compare the joint lowering candidates")
    args = parser.parse_args()
    engine = chain_metadata()
    if not os.environ.get("REGTEST_URL") or engine["commit"] != CONTEXT_PIN or args.samples < 1:
        parser.error("use pinned chain-gang, positive --samples, and tools/verify_node.sh")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    plan_by_name = {plan.name: plan for plan in plans()}
    auto = plan_by_name["compiler-auto"]
    manual, offset = compiled_template(bytes(20))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    variants, scaled_joint_codes, rewrites = {}, {}, {}
    batch_label = f"{GLV_SCALED}/dataflow/batch"
    if args.joint_lowerings:
        for strategy in JOINT_STRATEGIES:
            code_trace = [] if strategy == GLV_SCALED else None
            detached, lock, info, _ = compile_window_candidate(auto, linked=True, strategy=strategy, joint_code=code_trace)
            variants[strategy] = detached, lock
            rewrites[strategy] = info["runtime_rewrites"]
            if code_trace:
                scaled_joint_codes[strategy] = code_trace[0]
        dataflow = replace(auto, runtime=DATAFLOW)
        for batch in (False, True):
            label = f"{GLV_SCALED}/dataflow" + ("/batch" if batch else "")
            joint_code = []
            detached, lock, info, _ = compile_window_candidate(dataflow, linked=True, strategy=GLV_SCALED,
                                                               joint_code=joint_code, batch=batch)
            variants[label] = detached, lock
            scaled_joint_codes[label] = joint_code[0]
            rewrites[label] = info["runtime_rewrites"]
        for comparison in ("fused", "paired"):
            label = f"{batch_label}/{comparison}"
            joint_code = []
            detached, lock, info, _ = compile_window_candidate(dataflow, linked=True, strategy=GLV_SCALED,
                                                               joint_code=joint_code, batch=True,
                                                               comparison=comparison)
            variants[label] = detached, lock
            scaled_joint_codes[label] = joint_code[0]
            rewrites[label] = info["runtime_rewrites"]
    if args.matrix_only:
        activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
        if activation < 3:
            parser.error("use REGTEST_CHRONICLE_HEIGHT=5 for the transaction matrix")
        if variants:
            winner = min(variants, key=lambda name: len(variants[name][1]))
            _, lock = variants[winner]
        else:
            winner = "window-linked-auto"
            _, lock, _, _ = compile_window_candidate(auto, linked=True)
        rows = [replay_matrix(node, case, activation, (lock, offset)) for case in matrix_cases() if AUTO in case.sources]
        report = {"compiler": PROJECT_VERSION, "chain_gang": engine, "bsv_node": node.version,
                  "chronicle_height": activation,
                  "automatic_lock_sha256": sha256(lock).hexdigest(), "rows": rows}
        if variants:
            report["selected_automatic"] = winner
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        return
    builds = {"manual-v0.17.0": (verifier(), manual)}
    if variants:
        frozen = json.loads((HERE / "window-measurements.json").read_text())
        if sha256(variants[GLV_REFERENCE][1]).hexdigest() != frozen["results"]["window-linked-auto"]["lock_sha256"]:
            raise ValueError("joint reference differs from the frozen comparison")
        builds.update(variants)
    else:
        old = json.loads((HERE / "measurements.json").read_text())
        binary, lock, _, _ = compile_candidate(auto)
        builds["binary-auto"] = binary, lock
        if sha256(lock).hexdigest() != old["candidates"]["compiler-auto"]["lock_sha256"]:
            raise ValueError("binary control differs from the frozen comparison")
        for label, plan in (("window-baseline", "source-baseline"), ("window-auto", "compiler-auto")):
            code, lock, _, _ = compile_window_candidate(plan_by_name[plan])
            builds[label] = code, lock
        code, lock, _, _ = compile_window_candidate(auto, linked=True)
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
    timing_names = [name for name in builds if name != "window-baseline"]
    fixed = {name: compile_fixed_generator(curve).candidates for name, curve in CURVES.items()}
    report = {"compiler": PROJECT_VERSION, "chain_gang": engine, "bsv_node": node.version, "samples": args.samples,
              "timings_ms": measure(node, {name: timing_inputs[name] for name in timing_names}, args.samples),
              "fixed_generator_lowering": fixed, "results": rows,
              "selected_automatic": min((name for name in timing_names if name != "manual-v0.17.0"),
                                        key=lambda name: rows[name]["lock_bytes"])}
    if variants:
        selected = report["selected_automatic"]
        report["compiler_rewrites"] = rewrites
        report["output_model_regions"] = compare_output_regions(builds, batch_label)
        if selected in scaled_joint_codes:
            report["scaled_vs_manual_regions"] = compare_scaled_regions(
                builds["manual-v0.17.0"], builds[selected], scaled_joint_codes[selected],
            )
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

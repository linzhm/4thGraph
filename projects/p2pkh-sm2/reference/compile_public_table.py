"""Compile the SM2 public-key window table with the 4thGraph dataflow scheduler."""
import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path

from fourthgraph.bsv.script import number
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.stack_schedule import emit_steps

from point_kernels import CARRIED_KERNEL_FILE, CARRIED_KERNEL_NAMES, CARRIED_PASSES, CARRIED_SOURCE
from point_kernels import load_kernels, split_window_doublings


PUBLIC_TABLE_KERNEL = "sm2-public-table-kernel"


def compile_tables():
    carried = load_kernels(CARRIED_KERNEL_FILE, CARRIED_KERNEL_NAMES)
    compiler = ScriptBuilder.from_file(CARRIED_SOURCE, formula_passes=CARRIED_PASSES)
    doubles = {"shared": split_window_doublings(carried["sm2-window-double-five"]),
               "fresh": compiler.emit("sm2-double-with-prime", b"")}
    additions = {kind: compiler.emit(f"sm2-window-add-{kind}", b"") for kind in ("projective", "affine")}
    variants = {}
    for chain, kernel, addition, group_operands, trim_suffix in product(
        ("binary", "linear"), doubles, additions, (False, True), (False, True),
    ):
        if chain == "linear" and kernel == "fresh":
            continue  # Linear chains only use additions.
        # The caller checks Q. SM2 has cofactor 1 and 1..16 are below the
        # group order, so these doubles of finite points cannot reach infinity.
        qx, qy, b3, prime = inputs = (0, 1, 2, 3)
        one = 4
        points = {1: (qx, qy, one)}
        steps = [(number(1), (), (one,))]
        for multiple in range(2, 17):
            first = 5 + 3 * (multiple - 2)
            point = points[multiple] = (first, first + 1, first + 2)
            if chain == "binary" and multiple % 2 == 0:
                steps.append((doubles[kernel], (prime, *points[multiple // 2]), (prime, *point)))
            else:
                base = (qx, qy) if addition == "affine" else points[1]
                steps.append((additions[addition], (b3, prime, *points[multiple - 1], *base),
                              (b3, prime, *point)))
        returns = tuple(slot for point in points.values() for slot in point)
        plan = f"{chain}-{kernel}" if chain == "binary" else chain
        name = f"{plan}-{addition}-group{int(group_operands)}-trim{int(trim_suffix)}"
        variants[name] = emit_steps(inputs, steps, returns, compact=True,
                                    group_operands=group_operands, trim_suffix=trim_suffix)
    return variants


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--variant", default="binary-shared-affine-group1-trim1")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    variants = compile_tables()
    if args.variant not in variants:
        parser.error(f"unknown variant {args.variant}")
    args.output.write_text(json.dumps({PUBLIC_TABLE_KERNEL: variants[args.variant].hex()}, indent=2) + "\n",
                           encoding="utf-8")
    if args.report:
        report = {
            "selected": args.variant,
            "candidates": {name: {"bytes": len(code), "sha256": sha256(code).hexdigest()}
                           for name, code in variants.items()},
        }
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

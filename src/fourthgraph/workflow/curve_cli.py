"""Compile checked elliptic-curve multiplication and report the lowering cost."""
import argparse
import json

from fourthgraph.compiler.curve_lowering import compile_curve_multiply
from fourthgraph.compiler.curve_windows import CURVES, JOINT_STRATEGIES


def main(argv=None):
    parser = argparse.ArgumentParser(prog="4thgraph curve-multiply", description=__doc__)
    parser.add_argument("--curve", choices=CURVES, required=True)
    parser.add_argument("--operation", choices=("generator", "joint"), default="generator")
    parser.add_argument("--strategy", default="auto",
                        choices=("auto", "binary", "fixed-window-2", "fixed-window-4", *JOINT_STRATEGIES))
    parser.add_argument("--optimize", choices=("baseline", "safe", "stack"), default="stack")
    args = parser.parse_args(argv)
    curve = CURVES[args.curve]
    try:
        result = compile_curve_multiply(curve, args.operation, args.strategy, optimization=args.optimize)
    except ValueError as exc:
        parser.error(str(exc))
    effect = "( scalar -- X Y Z )" if args.operation == "generator" else "( Px Py s k -- p X Y Z )"
    print(json.dumps({"curve": curve.name, "operation": args.operation, "stack_effect": effect,
                      "selected": result.selected, "script_hex": result.script.hex(),
                      "candidates": result.candidates}, sort_keys=True))

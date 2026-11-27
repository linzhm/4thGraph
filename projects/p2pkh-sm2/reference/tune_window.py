"""Compare 4thGraph formula plans for the SM2 scalar window on fixed vectors."""
import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path

from assemble import AFFINE_KERNEL_FILE, POINT_KERNEL_FILE, WINDOW_KERNEL_FILE
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import encode_num
from fourthgraph.compiler.script_builder import ScriptBuilder
from point_kernels import AFFINE_KERNEL_NAME, CARRIED_KERNEL_NAMES, CARRIED_PASSES, CARRIED_SOURCE
from point_kernels import WINDOW_KERNEL_NAME, load_kernels
from sm2 import B, P, mul

PASS_PLANS = ((), ("stack",), ("stack", "search"), ("rewrite", "share", "stack"), CARRIED_PASSES)
RULE_ORDERS = ((), ("common-values",), ("double-as-add",),
               ("double-as-add", "factor-products"), ("factor-products", "double-as-add"))


def window_vectors():
    double, projective, affine = CARRIED_KERNEL_NAMES
    old = {
        double: load_kernels(WINDOW_KERNEL_FILE, (WINDOW_KERNEL_NAME,))[WINDOW_KERNEL_NAME],
        projective: load_kernels(POINT_KERNEL_FILE)["sm2-add-kernel"],
        affine: load_kernels(AFFINE_KERNEL_FILE, (AFFINE_KERNEL_NAME,))[AFFINE_KERNEL_NAME],
    }
    x, y = mul(19)
    j, k = mul(7)
    infinity = (0, -7, 0)
    point, inverse = (x, y, 1), (x, -y, 1)
    scaled = (-(2*j % P), -(2*k % P), -2)
    extremes = (P-1, 1-P, P-1)
    args = {
        double: (infinity, point, inverse, scaled, extremes),
        projective: tuple(a+b for a,b in ((infinity, infinity), (infinity, point), (point, infinity),
                                          (point, point), (point, inverse), (scaled, extremes))),
        affine: tuple(a+b[:2] for a,b in ((infinity, point), (point, point), (point, inverse),
                                         (scaled, inverse), (extremes, point))),
    }
    prefix = list(map(encode_num, (P, 3*B % P, 17)))
    constants = [prefix[1], prefix[0]]
    for name, vectors in args.items():
        for values in vectors:
            operands = list(map(encode_num, values))
            main, alt = evaluate(old[name], prefix+operands)
            yield name, prefix+constants+operands, (prefix+constants+main[len(prefix):], alt)


def evaluate_kernels(kernels, vectors):
    for name, stack, expected in vectors:
        if evaluate(kernels[name], stack) != expected:
            raise ValueError(f"{name} diverged from template 9 for {stack}")


def tune():
    vectors = list(window_vectors())
    candidates = []
    for passes, rules in product(PASS_PLANS, RULE_ORDERS):
        if not passes and rules:
            continue
        compiler = ScriptBuilder.from_file(CARRIED_SOURCE, formula_passes=passes, experimental_rules=rules)
        kernels = {name: compiler.emit(name, b"") for name in CARRIED_KERNEL_NAMES}
        evaluate_kernels(kernels, vectors)
        sizes = {name: len(code) for name, code in kernels.items()}
        double, projective, affine = CARRIED_KERNEL_NAMES
        # There are 51 doubling groups and 52 emitted additions for each table.
        cost = 51*sizes[double] + 52*(sizes[projective]+sizes[affine])
        candidates.append({"passes": passes, "ordered_rules": rules, "kernel_bytes": sizes,
                           "window_kernel_bytes": cost, "checks": len(vectors),
                           "rule_applications": {name: details.get("ordered_rules", [])
                                                 for name, details in compiler.formulas.items()}})
    winner = min(candidates, key=lambda row: (row["window_kernel_bytes"], len(row["passes"]),
                                              len(row["ordered_rules"])))
    if winner["passes"] != CARRIED_PASSES or winner["ordered_rules"]:
        raise ValueError("The pinned template plan no longer wins the fixed comparison")
    traced = ScriptBuilder.from_file(CARRIED_SOURCE, formula_passes=CARRIED_PASSES, trace_formulas=True)
    return {"candidates": candidates, "selected": winner, "lowering": traced.formulas,
            "kernel_sha256": {name: sha256(traced.emit(name, b"")).hexdigest() for name in CARRIED_KERNEL_NAMES},
            "target_stack_plan": {name: {"order": plan["order"], "search": plan["search"],
                                         "inputs": plan["inputs"], "returns": plan["returns"],
                                         "schedule_sha256": sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()}
                                  for name, plan in traced.formula_stack_plans.items()}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    args.report.write_text(json.dumps(tune(), indent=2) + "\n", encoding="utf-8")

"""Same-source differential checks for the formula builder's public pass options."""

from itertools import product
from operator import add, mul, sub
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, encode_num
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.source import CompileError


# Integer numerators of a quadratic Bézier coordinate and its derivative.
# The parameter is t/16. The returns have denominators 256 and 16.
SOURCE = (Path(__file__).resolve().parents[1] / "src/fourthgraph/benchmark/formulas/bezier.fth").read_text()
ENTRY = "bezier-coordinate"
BASELINE = ()
ALL = ("rewrite", "share", "stack", "search")
PLANS = (BASELINE, ("rewrite",), ("share",), ("stack",), ("stack", "search"),
         ("rewrite", "share"), ("rewrite", "share", "stack"), ALL)


def coordinate_and_tangent(p0, p1, p2, t):
    u = 16 - t
    position = p0 * u**2 + 2 * p1 * t * u + p2 * t**2
    tangent = 2 * ((p1 - p0) * u + (p2 - p1) * t)
    return position, tangent


class FormulaPassTests(unittest.TestCase):
    def test_ordered_cross_products_inline_a_closed_formula(self):
        source = """REQUIRE BSV
range: limb script-int -9 10 ;
range: wide script-int -500 501 ;
formula: product ( limb limb limb limb -- wide wide )
    {: a b c d :}
    a c int* let ac
    b d int* let bd
    ac bd int-
    a b int+ c d int+ int* ac int- bd int-
;
"""
        baseline = ScriptBuilder(source, formula_passes=("stack",))
        optimized = ScriptBuilder(source, formula_passes=("stack",), experimental_rules=("expand-cross-products",))
        kernel = optimized.formula_ir["product"]
        operations = {"int+": add, "int-": sub, "int*": mul}
        for args in product((-9, 0, 9), repeat=4):
            calls = []

            def lower(name, *operands):
                calls.append(name)
                return operations[name](*operands)

            expected = baseline.formula_ir["product"].inline(args, lambda name, *args: operations[name](*args))
            self.assertEqual(kernel.inline(args, lower), expected)
            self.assertEqual(calls, ["int*", "int*", "int-", "int*", "int*", "int+"])
        with self.assertRaisesRegex(ValueError, "outside its input interval"):
            kernel.inline((10, 0, 0, 0), lower)

    def test_passes_preserve_exact_signed_results_and_both_stacks(self):
        values = (-128, -1, 0, 1, 127)
        prefix = b"\x81"
        alt = b"sentinel"
        for plan in PLANS:
            builder = ScriptBuilder(SOURCE, formula_passes=plan)
            code = builder.emit(ENTRY, asm("OP_TOALTSTACK"))
            with self.subTest(plan=plan):
                for operands in product(values, values, values, (0, 1, 8, 15, 16)):
                    initial = [prefix, *map(encode_num, operands), alt]
                    expected = [prefix, *map(encode_num, coordinate_and_tangent(*operands))]
                    self.assertEqual(evaluate(code, initial), (expected, [alt]), operands)

    def test_default_modes_and_explicit_report(self):
        default = ScriptBuilder(SOURCE)
        automatic = ScriptBuilder(SOURCE, optimize=True)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bezier.fth"
            path.write_text(SOURCE, encoding="utf-8")
            disabled = ScriptBuilder.from_file(path, formula_passes=())
            ordered = ScriptBuilder.from_file(path, formula_passes=ALL)
            reversed_order = ScriptBuilder.from_file(path, formula_passes=reversed(ALL))
        self.assertEqual(disabled.emit(ENTRY, b""), default.emit(ENTRY, b""))
        self.assertEqual(default.formulas[ENTRY]["selected"], "baseline")
        self.assertEqual(set(automatic.formulas[ENTRY]["candidates"]),
                         {"baseline", "schedule", "rewrite-and-schedule"})
        self.assertEqual(len(automatic.emit(ENTRY, b"")), min(automatic.formulas[ENTRY]["candidates"].values()))
        self.assertEqual(ordered.emit(ENTRY, b""), reversed_order.emit(ENTRY, b""))
        self.assertEqual(ordered.formulas, reversed_order.formulas)
        self.assertEqual(ordered.formulas[ENTRY]["passes"], ALL)
        self.assertEqual(ordered.formulas[ENTRY]["script_bytes"], len(ordered.emit(ENTRY, b"")))
        self.assertEqual(ordered.formulas[ENTRY]["rewrites"]["multiply-by-two-as-addition"], 2)
        self.assertEqual(ordered.formulas[ENTRY]["max_magnitude_bits"], disabled.formulas[ENTRY]["max_magnitude_bits"])

    def test_range_proof_and_configuration_errors(self):
        bad_range = SOURCE.replace("position script-int -131072 131073", "position script-int -1 2")
        possibly_zero_divisor = SOURCE.replace("p2 t t int* int* int+", "p2 t int-rem int+")
        for plan in (BASELINE, ALL):
            for source, error in ((bad_range, "results do not fit"), (possibly_zero_divisor, "positive divisor")):
                with self.subTest(plan=plan, error=error), self.assertRaisesRegex(CompileError, error):
                    ScriptBuilder(source, formula_passes=plan)
        for names, error in ((("search",), "requires stack"), (("share", "share"), "repeated"),
                             (("unknown",), "unknown")):
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, error):
                ScriptBuilder(SOURCE, formula_passes=names)
        with self.assertRaisesRegex(ValueError, "automatic formula optimization"):
            ScriptBuilder(SOURCE, optimize=True, formula_passes=())

    def test_reuse_remainder_only_for_the_same_divisor(self):
        source = """REQUIRE BSV
range: coordinate script-int -100 101 ;
range: modulus script-int 1 8 ;
range: residue script-int -6 7 ;
formula: repeated ( coordinate modulus -- residue )
    {: n d :} n d int-rem d int-rem ;
formula: different ( coordinate modulus modulus -- residue )
    {: n first second :} n first int-rem second int-rem ;
"""
        baseline = ScriptBuilder(source, formula_passes=())
        optimized = ScriptBuilder(source, formula_passes=("rewrite", "share", "stack"))
        rule = "reuse-same-divisor-remainder"
        self.assertEqual(optimized.formulas["repeated"]["rewrites"][rule], 1)
        self.assertNotIn(rule, optimized.formulas["different"]["rewrites"])
        self.assertLess(len(optimized.emit("repeated", b"")), len(baseline.emit("repeated", b"")))
        for entry, operands in (("repeated", (-19, 7)), ("repeated", (19, 7)), ("different", (-19, 7, 3))):
            with self.subTest(entry=entry, operands=operands):
                stack = list(map(encode_num, operands))
                self.assertEqual(evaluate(optimized.emit(entry, b""), stack),
                                 evaluate(baseline.emit(entry, b""), stack))

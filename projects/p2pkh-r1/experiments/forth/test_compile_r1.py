from itertools import product
from importlib import import_module
from random import Random
import unittest

from compile_r1 import SOURCE, compile_source, previous_build
from curve_compiler import B3, FIELD
from fixed_templates import compiled_template, otda_pattern
from replay_r1 import template
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import encode_num


class CompileR1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.unoptimized = compile_source(cls.source, bytes(20))
        cls.optimized = compile_source(cls.source, bytes(20), optimize=True)

    def test_complete_lock_and_otda_cost(self):
        reference = compiled_template(scheduled=True)
        hand = previous_build(bytes(20), optimize=False)
        self.assertEqual(hand.emit("r1-lock", b""), reference.script)
        previous, _, _ = template(self.source, mode="previous-forth")
        lock, pattern, report = template(self.source, mode="optimized")
        self.assertEqual(len(previous.script), 45_776)
        self.assertLess(len(lock.script), len(previous.script))
        self.assertLess(len(pattern.program), len(otda_pattern(scheduled=True)[1].program))
        self.assertEqual(report["r1-add-points"]["rewrites"]["expand-cross-products"], 3)
        self.assertEqual(report["r1-double-finite"]["rewrites"]["multiply-by-two-as-addition"], 4)

        # Attribute every changed byte in each full lock to one of the two formulas.
        for build, original in ((hand, reference.script),
                                (self.unoptimized, self.unoptimized.emit("r1-lock", b""))):
            for entry, copies in (("r1-add-points", 135), ("r1-double-point", 263)):
                kernel = build.emit(entry, b"")
                self.assertEqual(original.count(kernel), copies)
                original = original.replace(kernel, self.optimized.emit(entry, b""))
            self.assertEqual(original, lock.script)

    def test_formula_rejects_unproven_ranges(self):
        builder = import_module("fourthgraph.compiler.script_builder")
        declaration = """
            range: coordinate script-int -10 11 ;
            formula: reduce ( coordinate coordinate -- coordinate )
                {: value divisor :}
                value divisor {}
            ;
        """
        for operator, error in (("int-rem", "positive divisor"), ("int*", "declared stack effect and ranges")):
            with self.subTest(operator=operator), self.assertRaisesRegex(builder.CompileError, error):
                builder.ScriptBuilder(declaration.replace("{}", operator), optimize=True)

    def test_exact_signed_projective_results_at_range_edges(self):
        rng = Random(256)
        edges = (0, 1, -1, FIELD - 1, 1 - FIELD)
        # Exercise the bottom-relative constants with an unrelated main-stack item.
        prefix = list(map(encode_num, (FIELD, B3, 847)))
        previous = previous_build(bytes(20), optimize=True)
        for entry, arity in (("r1-add-points", 6), ("r1-double-point", 3)):
            codes = [build.emit(entry, b"") for build in (previous, self.unoptimized, self.optimized)]
            vectors = [tuple((a, b)[index % 2] for index in range(arity)) for a, b in product(edges, repeat=2)]
            vectors.extend(tuple(rng.randrange(1 - FIELD, FIELD) for _ in range(arity)) for _ in range(128))
            for coordinates in vectors:
                with self.subTest(entry=entry, coordinates=coordinates):
                    start = prefix + list(map(encode_num, coordinates))
                    expected, alternate = evaluate(codes[0], start)
                    self.assertEqual(expected[:len(prefix)], prefix)
                    self.assertEqual(len(expected), len(prefix) + 3)
                    self.assertEqual(alternate, [])
                    for code in codes[1:]:
                        self.assertEqual(evaluate(code, start), (expected, alternate))


if __name__ == "__main__":
    unittest.main()

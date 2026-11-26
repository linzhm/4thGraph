"""Regression checks for interval proofs and untrusted entry encodings."""

from pathlib import Path
import unittest

from compiler import CompileError, SourceCompiler, evaluate
from lowering import compile_word
from shared.evaluate import ScriptError, evaluate as evaluate_script
from shared.script import decode_num, encode_num

EXAMPLE = Path(__file__).resolve().parents[1] / "p2pkh-r1/experiments/forth/window-ranges.fth"
SOURCE = EXAMPLE.read_text()


class RangeTests(unittest.TestCase):
    def test_window_ranges_are_proved_and_remainder_is_removed(self):
        word = SourceCompiler(SOURCE).words["q-depth-probe"]
        for check in (False, True):
            baseline = compile_word(word, "baseline", check_input_ranges=check)
            optimized = compile_word(word, "safe", check_input_ranges=check)
            rule, = optimized.rewrites
            self.assertEqual(rule.rule, "integer-remainder-in-range")
            self.assertEqual(rule.inputs[0].bounds, (5, 50))
            self.assertEqual(rule.script_bytes, (3, 0))
            self.assertEqual(len(baseline.script) - len(optimized.script), 3)
            for digit in range(16):
                expected = (50 - 3 * digit,)
                self.assertEqual(evaluate(word, digit), expected)
                for candidate in (baseline, optimized):
                    stack, alt = evaluate_script(candidate.script, [encode_num(digit)])
                    self.assertEqual((tuple(map(decode_num, stack)), alt), (expected, []))
        with self.assertRaisesRegex(CompileError, r"script-int \[5, 51\).*declared"):
            SourceCompiler(SOURCE.replace("script-int 5 51", "script-int 6 51"))

    def test_unchecked_calls_and_branch_results_cannot_claim_a_range(self):
        invalid_call = "bsv-effect: invalid script-int -- r1-q-depth ;\n: invalid q-pick-depth ;"
        with self.assertRaisesRegex(CompileError, "expected stack suffix"):
            SourceCompiler(SOURCE + invalid_call)
        invalid_branch = ("bsv-effect: invalid r1-digit cell -- r1-digit ;\n"
                          ": invalid IF DROP 16 cell>int THEN ;")
        with self.assertRaisesRegex(CompileError, r"\[0, 17\).*declared"):
            SourceCompiler(SOURCE + invalid_branch)
        with self.assertRaisesRegex(CompileError, "exceeds the value range of cell"):
            SourceCompiler("range: overflowing cell 0 9223372036854775809 ;")

    def test_checked_exports_and_explicit_checks_reject_malformed_inputs(self):
        words = SourceCompiler(SOURCE).words
        for mode in ("baseline", "safe", "stack"):
            checked = compile_word(words["q-depth-probe"], mode).script
            explicit = compile_word(words["checked-q-depth"], mode, check_input_ranges=False).script
            assumed = compile_word(words["q-depth-probe"], mode, check_input_ranges=False).script
            self.assertEqual(checked, explicit)
            self.assertEqual(len(checked) - len(assumed), 9)
            bad_values = (encode_num(-1), encode_num(16), encode_num(1 << 512), b"\x00", b"\x80", b"\x01\x00")
            for value in bad_values:
                for script in (checked, explicit):
                    with self.assertRaises(ScriptError):
                        evaluate_script(script, [value])
        with self.assertRaisesRegex(ValueError, "out of range for r1-digit"):
            evaluate(words["q-depth-probe"], 16)

    def test_zero_divisor_and_unused_guard_still_fail(self):
        source = SOURCE + """
bsv-effect: remainder r1-digit r1-digit -- script-int ;
: remainder int-rem ;
bsv-effect: discard-checked script-int -- cell ;
: discard-checked check-range r1-digit DROP 1 ;
"""
        words = SourceCompiler(source).words
        for mode in ("baseline", "safe", "stack"):
            remainder = compile_word(words["remainder"], mode)
            self.assertFalse(any(rule.rule == "integer-remainder-in-range" for rule in remainder.rewrites))
            self.assertEqual(evaluate_script(remainder.script, [encode_num(15), encode_num(4)]), ([b"\x03"], []))
            with self.assertRaises(ScriptError):
                evaluate_script(remainder.script, [encode_num(15), b""])
            discarded = compile_word(words["discard-checked"], mode)
            with self.assertRaises(ScriptError):
                evaluate_script(discarded.script, [encode_num(16)])

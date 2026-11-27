"""Regression checks for interval proofs and untrusted entry encodings."""

import os
from pathlib import Path
import unittest

from fourthgraph.compiler.source import CompileError, SourceCompiler, evaluate
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.bsv.evaluate import ScriptError, evaluate as evaluate_script
from fourthgraph.bsv.script import asm, decode_num, encode_num
from fourthgraph.compiler.wordsets import CELL_SIGN, U32, push_value

EXAMPLE = Path(__file__).resolve().parents[1] / "projects/p2pkh-r1/forth" / "window-ranges.fth"
SOURCE = EXAMPLE.read_text()


NUMERIC_ENTRIES = """
REQUIRE BSV
: ordinary ( u32 -- cell ) u32>cell cell>u32 u32>cell 0 > ;
lock: direct ( amount:u32 ) amount u32>cell 0 > verify ;
lock: mixed ( wide:cell unsigned:u32 choice:route unbounded:script-int ) 1 ;
"""


def numeric_entry_cases():
    words = SourceCompiler(NUMERIC_ENTRIES).words
    mixed = tuple(map(encode_num, (-CELL_SIGN, U32 - 1, 1, 1 << 80)))
    for mode in ("baseline", "safe", "stack"):
        for name in ("ordinary", "direct"):
            script = compile_word(words[name], mode, spend_entry=name == "ordinary").script
            yield mode, name, script, (encode_num(U32 - 1),), True
            for invalid in (encode_num(U32), encode_num(-1), b"\x01\x00", b"\x80"):
                yield mode, name, script, (invalid,), False
        script = compile_word(words["mixed"], mode).script
        yield mode, "mixed", script, mixed, True
        for depth, invalid in ((0, encode_num(CELL_SIGN)), (0, encode_num(-CELL_SIGN - 1)),
                               (1, encode_num(U32)), (2, encode_num(2)), (3, b"\x00"), (3, b"\x80")):
            yield mode, "mixed", script, mixed[:depth] + (invalid,) + mixed[depth + 1:], False


class RangeTests(unittest.TestCase):
    def test_spend_entries_check_basic_numeric_types_before_optimization(self):
        for mode, name, script, inputs, accepted in numeric_entry_cases():
            with self.subTest(mode=mode, entry=name, inputs=inputs):
                if accepted:
                    stack, alt = evaluate_script(script, list(inputs))
                    self.assertNotEqual(decode_num(stack[0]), 0)
                    self.assertEqual((len(stack), alt), (1, []))
                else:
                    with self.assertRaisesRegex(ScriptError, "VERIFY"):
                        evaluate_script(script, list(inputs))

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires tools/verify_node.sh")
    def test_numeric_spend_entries_match_both_engines(self):
        from fourthgraph.benchmark.validation import Node
        from fourthgraph.bsv.chain_gang import validate_at_heights
        from fourthgraph.bsv.transaction import Input, Output, Transaction

        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
        for version, funding, height in ((1, activation - 1, activation - 1),
                                         (2, activation - 1, activation + 1),
                                         (2, activation, activation + 1)):
            context = dict(activation_height=activation, spend_height=height, utxo_heights=(funding,))
            for mode, name, script, inputs, accepted in numeric_entry_cases():
                with self.subTest(version=version, funding=funding, mode=mode, entry=name, inputs=inputs):
                    parent = Transaction((Input(bytes([23]) * 32, 0),), (Output(1000, script),))
                    witness = b"".join(map(push_value, inputs))
                    tx = Transaction((Input(parent.txid_wire(), 0, script=witness),),
                                     (Output(900, asm("OP_1")),), version=version)
                    self.assertEqual(node.verdicts(tx, (parent,), **context), [accepted])
                    if accepted:
                        validate_at_heights(tx, (parent,), **context)
                    else:
                        with self.assertRaises((ValueError, RuntimeError)):
                            validate_at_heights(tx, (parent,), **context)

    def test_named_lock_checks_ranges_for_inputs_it_drops(self):
        source = """
range: admitted cell 1 3 ;
lock: entry ( value:admitted ) value drop 1 ;
"""
        word = SourceCompiler(source).words["entry"]
        for mode in ("baseline", "safe", "stack"):
            with self.subTest(mode=mode):
                script = compile_word(word, mode).script
                for value in (1, 2):
                    self.assertEqual(evaluate_script(script, [encode_num(value)]), ([b"\x01"], []))
                for value in (0, 3):
                    with self.assertRaisesRegex(ScriptError, "VERIFY"):
                        evaluate_script(script, [encode_num(value)])
                with self.assertRaisesRegex(CompileError, "expansion budget"):
                    compile_word(word, mode, max_expansion=2)

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

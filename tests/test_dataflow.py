"""Exercise reusable dataflow rules across checked bytes and stack boundaries."""
import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num
from fourthgraph.compiler.lowering import DATAFLOW, compile_word
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.source import CompileError, SourceCompiler
from fourthgraph.compiler.stack_schedule import emit_steps
from fourthgraph.compiler.wordsets import script_word


class DataflowTests(unittest.TestCase):
    def test_layout_declarations_work_in_the_standard_frontend(self):
        source = SourceCompiler("""
            layout: copy-letter ( letter:bytes ignored:cell -- letter letter )
            : repeat-letter ( bytes cell -- bytes bytes ) copy-letter ;
        """)
        code = compile_word(source.words["repeat-letter"], DATAFLOW).script
        self.assertEqual(evaluate(code, [b"a", encode_num(7)]), ([b"a", b"a"], []))
        with self.assertRaisesRegex(CompileError, "layout results"):
            SourceCompiler("layout: invalid ( item:bytes -- unknown )")

    def test_trim_dead_prefix_preserves_live_suffix_and_caller_stacks(self):
        marker = b"reserved by the caller"
        for dead in (0, 1, 2, 7, 38, 75):
            for live in (0, 1, 2, 4, 6):
                inputs = tuple(range(dead + live))
                returns = inputs[dead:]
                plain = emit_steps(inputs, (), returns)
                compact = emit_steps(inputs, (), returns, trim_suffix=True)
                self.assertLessEqual(len(compact), len(plain))
                if dead == 75:
                    self.assertLess(len(compact), len(plain))
                stack = [marker, *map(encode_num, inputs)]
                actual = evaluate(asm("17 OP_TOALTSTACK") + compact, stack)
                self.assertEqual(actual, ([marker, *map(encode_num, returns)], [encode_num(17)]))
        inputs = (0, 1, 2, 3, 4, 5)
        returns = (2, 1, 2)
        code = emit_steps(inputs, (), returns, trim_suffix=True)
        self.assertEqual(evaluate(code, list(map(encode_num, inputs))), (list(map(encode_num, returns)), []))

    def test_width_proof_controls_library_replacement_and_sharing(self):
        library = ScriptBuilder("REQUIRE stdlib/script-fragments.fth")
        decode = script_word("bytes", "script-int", library.emit("script-uint256be", b""),
                             lambda value: int.from_bytes(value, "big"), repeatable=True,
                             fixed_width_code=(32, library.emit("script-uint256be-compact", b"")))
        source = SourceCompiler("""
            REQUIRE BSV
            lock: known ( data:bytes )
                data 64 bytes-check-size 32 op_split drop decode drop
                data 64 bytes-check-size 32 op_split drop decode drop 1
            ;
            lock: unknown ( data:bytes ) data decode drop data decode drop 1 ;
        """, vocabulary={"decode": decode})
        known = compile_word(source.words["known"], DATAFLOW)
        rules = [entry.rule for entry in known.rewrites]
        self.assertEqual(rules.count("fixed-width-replacement"), 1)
        self.assertIn("reuse-dominating-expression", rules)
        self.assertLess(len(known.script), len(compile_word(source.words["known"], "stack").script))
        self.assertEqual(evaluate(known.script, [bytes(range(64))]), ([b"\x01"], []))
        for width in (0, 31, 63, 65):
            with self.assertRaises(ScriptError):
                evaluate(known.script, [bytes(width)])
        unknown = compile_word(source.words["unknown"], DATAFLOW)
        self.assertFalse(unknown.rewrites)
        self.assertEqual(unknown.script, compile_word(source.words["unknown"], "stack").script)

    def test_a_conditional_check_does_not_dominate_a_later_check(self):
        source = SourceCompiler("""
            REQUIRE BSV
            lock: guarded ( data:bytes choice:cell )
                choice IF data 32 bytes-check-size drop THEN
                data 32 bytes-check-size drop 1
            ;
        """)
        script = compile_word(source.words["guarded"], DATAFLOW).script
        for option in (b"", b"\x01"):
            self.assertEqual(evaluate(script, [bytes(32), option]), ([b"\x01"], []))
            with self.assertRaises(ScriptError):
                evaluate(script, [bytes(31), option])

    def test_shared_decoder_preserves_field_order_and_unsigned_high_bits(self):
        library = ScriptBuilder("REQUIRE stdlib/script-fragments.fth")
        for count in (1, 2, 3, 6, 7):
            fields = [bytes((128 + n + 13 * j) % 256 for j in range(32)) for n in range(count)]
            for values in (fields, [bytes(32)] * count, [bytes([255]) * 32] * count):
                script = library.emit("script-uint256be-fields", b"", count)
                result, alt = evaluate(script, [b"caller", b"".join(values)])
                self.assertEqual((result[0], alt), (b"caller", []))
                self.assertEqual(list(map(decode_num, result[1:])), [int.from_bytes(value, "big") for value in values])
            with self.assertRaises(ScriptError):
                evaluate(script, [bytes(count * 32 + 1)])

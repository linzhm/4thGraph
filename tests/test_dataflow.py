"""Exercise reusable dataflow rules across checked bytes and stack boundaries."""
import unittest
from dataclasses import replace

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num
from fourthgraph.compiler.lowering import DATAFLOW, compile_word
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.source import CompileError, SourceCompiler
from fourthgraph.compiler.stack_schedule import emit_steps
from fourthgraph.compiler.wordsets import Primitive, script_word


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

    def test_layout_scheduling_supports_multiple_returns_and_requires_local_operands(self):
        two_results = Primitive(("script-int", "script-int"), ("script-int", "script-int"),
                                asm("OP_2DUP OP_SUB OP_TOALTSTACK OP_ADD OP_FROMALTSTACK"),
                                lambda left, right: (left + right, left - right),
                                "sum and difference", stack_local=True)
        program = """
            layout: exchange ( first:script-int second:script-int -- second first )
            : combine ( script-int script-int -- script-int script-int )
                exchange exchange both-results
            ;
        """
        word = SourceCompiler(program, vocabulary={"both-results": two_results}).words["combine"]
        plain, optimized = (compile_word(word, mode) for mode in ("stack", DATAFLOW))
        self.assertLess(len(optimized.script), len(plain.script))
        self.assertIn("layout-value-aliasing", {rule.rule for rule in optimized.rewrites})
        stack = [b"caller", encode_num(7), encode_num(2)]
        actual = evaluate(asm("17 OP_TOALTSTACK") + optimized.script, stack)
        self.assertEqual(actual, ([b"caller", encode_num(9), encode_num(5)], [encode_num(17)]))
        opaque = replace(two_results, stack_local=False)
        word = SourceCompiler(program, vocabulary={"both-results": opaque}).words["combine"]
        self.assertEqual(compile_word(word, DATAFLOW).script, compile_word(word, "stack").script)

    def test_lock_layout_aliases_keep_branch_result_order(self):
        source = SourceCompiler("""
            REQUIRE BSV
            layout: exchange ( first:cell second:cell -- second first )
            lock: select ( left:cell right:cell flag:cell )
                left right exchange exchange flag IF exchange ELSE exchange exchange THEN -
            ;
        """)
        word = source.words["select"]
        plain, optimized = (compile_word(word, mode) for mode in ("stack", DATAFLOW))
        self.assertLess(len(optimized.script), len(plain.script))
        self.assertIn("layout-value-aliasing", {rule.rule for rule in optimized.rewrites})
        for flag, result in ((0, 5), (-1, -5)):
            with self.subTest(flag=flag):
                stack = [b"caller", *map(encode_num, (7, 2, flag))]
                actual = evaluate(asm("17 OP_TOALTSTACK") + optimized.script, stack)
                self.assertEqual(actual, ([b"caller", encode_num(result)], [encode_num(17)]))

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

    def test_trim_interleaved_dead_slots_preserves_a_return_subsequence(self):
        inputs = (0, 1, 2, 3, 4, 5)
        returns = (0, 2, 4, 5)
        compact = emit_steps(inputs, (), returns, trim_suffix=True)
        self.assertLess(len(compact), len(emit_steps(inputs, (), returns)))
        output, alt = evaluate(asm("17 OP_TOALTSTACK") + compact, [b"caller", *map(encode_num, inputs)])
        self.assertEqual((output, alt), ([b"caller", *map(encode_num, returns)], [encode_num(17)]))

    def test_grouped_operands_repush_a_single_byte_literal(self):
        source = SourceCompiler("""
            REQUIRE BSV
            layout: rotate-three ( a:cell b:cell c:cell -- c a b )
            lock: grouped ( a:cell b:cell ) a b 1 rotate-three - - ;
        """)
        stack = [b"caller", encode_num(5), encode_num(11)]
        for optimization in ("stack", DATAFLOW):
            with self.subTest(optimization=optimization):
                code = compile_word(source.words["grouped"], optimization).script
                result = evaluate(asm("17 OP_TOALTSTACK") + code, stack)
                self.assertEqual(result, ([b"caller", encode_num(7)], [encode_num(17)]))

    def test_grouped_operands_preserve_copies_and_last_uses(self):
        cases = (
            ((0, 1, 2, 3, 4, 5), (0, 1, 2, 3), (4, 5), "OP_2ROT"),
            ((0, 1, 2), (0, 1, 2), (0, 1, 2), "OP_3DUP"),
        )
        for inputs, args, kept, opcode in cases:
            outputs = tuple(range(len(inputs), len(inputs) + len(args)))
            steps = ((b"", args, outputs),)  # The called kernel returns each input unchanged.
            returns = (*kept, *outputs)
            grouped = emit_steps(inputs, steps, returns, compact=True, group_operands=True)
            self.assertIn(asm(opcode), grouped)
            self.assertLess(len(grouped), len(emit_steps(inputs, steps, returns, compact=True)))
            values = [b"caller", *map(encode_num, inputs)]
            self.assertEqual(evaluate(grouped, values), ([b"caller", *map(encode_num, (*kept, *args))], []))

    def test_scheduler_moves_an_operand_preserved_by_the_called_word(self):
        # Both operations consume p, x and return the very same p with 2*x.
        double = asm("OP_DUP OP_ADD")
        steps = ((double, (0, 1), (0, 2)), (double, (0, 2), (0, 3)))
        compact = emit_steps((0, 1), steps, (0, 3), compact=True, group_operands=True)
        self.assertEqual(compact, double * 2)
        self.assertLess(len(compact), len(emit_steps((0, 1), steps, (0, 3), compact=True)))
        out = evaluate(compact, [b"caller", encode_num(19), encode_num(-3)])
        self.assertEqual(out, ([b"caller", encode_num(19), encode_num(-12)], []))

    def test_dataflow_tiles_bounded_concat_chains_without_observed_intermediates(self):
        compiler = SourceCompiler("""
            REQUIRE BSV
            lock: repeat-checked ( seed:bytes expected:bytes )
                seed 3 bytes-check-size dup
                5 0 DO over bytes-cat LOOP nip expected bytes=
            ;
            lock: repeat-unchecked ( seed:bytes expected:bytes )
                seed dup 5 0 DO over bytes-cat LOOP nip expected bytes=
            ;
            lock: keep-intermediate ( seed:bytes twice:bytes four:bytes )
                seed 3 bytes-check-size dup bytes-cat
                dup dup bytes-cat four bytes= verify twice bytes=
            ;
        """)
        checked = compile_word(compiler.words["repeat-checked"], DATAFLOW)
        plain = compile_word(compiler.words["repeat-checked"], "stack")
        self.assertIn("tile-repeated-bytes", [rewrite.rule for rewrite in checked.rewrites])
        self.assertLess(len(checked.script), len(plain.script))
        self.assertEqual(evaluate(checked.script, [b"abc", b"abc" * 6]), ([encode_num(-1)], []))
        self.assertEqual(evaluate(checked.script, [b"abc", b"abc" * 5]), ([b""], []))
        with self.assertRaises(ScriptError):
            evaluate(checked.script, [b"ab", b"ab" * 6])
        for name in ("repeat-unchecked", "keep-intermediate"):
            code = compile_word(compiler.words[name], DATAFLOW)
            self.assertNotIn("tile-repeated-bytes", [rewrite.rule for rewrite in code.rewrites])
        code = compile_word(compiler.words["keep-intermediate"], DATAFLOW).script
        self.assertEqual(evaluate(code, [b"abc", b"abc" * 2, b"abc" * 4]), ([encode_num(-1)], []))

    def test_assertion_fusion_requires_an_unobserved_flag(self):
        source = SourceCompiler("""
            REQUIRE BSV
            lock: checked ( a:cell b:cell ) a b = verify 1 ;
            lock: observed ( a:cell b:cell ) a b = dup verify ;
        """)
        checks = compile_word(source.words["checked"], DATAFLOW)
        self.assertIn("comparison-feeds-verify", [rewrite.rule for rewrite in checks.rewrites])
        self.assertIn(asm("OP_NUMEQUALVERIFY"), checks.script)
        self.assertEqual(evaluate(checks.script, [encode_num(2)] * 2), ([encode_num(1)], []))
        with self.assertRaises(ScriptError):
            evaluate(checks.script, [encode_num(2), encode_num(3)])
        observed = compile_word(source.words["observed"], DATAFLOW)
        self.assertNotIn("comparison-feeds-verify", [rewrite.rule for rewrite in observed.rewrites])
        self.assertEqual(evaluate(observed.script, [encode_num(2)] * 2), ([encode_num(-1)], []))

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

    def test_build_time_tiling_transforms_only_the_runtime_top_item(self):
        builder = ScriptBuilder(": tile ( script cell -- script ) bsv-tile-top ;")
        for count in (1, 2, 3, 6, 9, 31, 256, 257):
            code = builder.emit("tile", b"", count)
            self.assertEqual(evaluate(code, [b"outer", b"seed"]), ([b"outer", b"seed" * count], []))
        self.assertEqual(len(builder.emit("tile", b"", 6)), 6)
        for bad in (0, -1):
            with self.assertRaisesRegex(CompileError, "requires a positive count"):
                builder.emit("tile", b"", bad)

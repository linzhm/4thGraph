"""Cross-backend checks for Script graph lowering."""

import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.compiler.stack_schedule import Graph, Value


class StackScheduleTests(unittest.TestCase):
    def test_assertions_consume_flags_and_preserve_other_uses(self):
        graph = Graph(1)
        operand, = graph.inputs
        flag = graph.define(asm("OP_0NOTEQUAL"), (operand,))
        one = graph.define(asm("OP_1"))
        equal = graph.define(asm("OP_EQUAL"), (flag, one))
        script = graph.emit_assertions((equal, flag, flag), compact=True)
        self.assertEqual(script, graph.emit_assertions((flag, equal), compact=True))
        self.assertIn(asm("OP_EQUALVERIFY"), script)
        prefix = b"underneath"
        self.assertEqual(evaluate(script, [prefix, encode_num(-1)]), ([prefix], []))
        with self.assertRaises(ScriptError):
            evaluate(script, [prefix, b""])

    def test_input_assertions_and_undefined_flags(self):
        graph = Graph(1)
        self.assertEqual(graph.emit_assertions(graph.inputs, compact=True), asm("OP_VERIFY"))
        with self.assertRaisesRegex(ValueError, "undefined"):
            graph.emit_assertions((Value(1),))

    def test_assertion_schedule_selects_the_shorter_order(self):
        for order, dependencies_win in (((0, 2, 1, 3), True), ((0, 1, 2, 3), False)):
            with self.subTest(order=order):
                graph = Graph(4)
                a, b, c, d = (graph.inputs[index] for index in order)
                difference = graph.define(asm("OP_SUB"), (a, b))
                first = graph.define(asm("OP_0NOTEQUAL"), (c,))
                balance = graph.define(asm("OP_SUB"), (difference, d))
                second = graph.define(asm("OP_NOT"), (balance,))
                source = graph.emit_assertions((first, second), compact=True)
                chosen = graph.emit_assertions((second, first), compact=True, reorder=True)
                if dependencies_win:
                    self.assertLess(len(chosen), len(source))
                    self.assertLess(chosen.index(asm("OP_VERIFY")), chosen.index(asm("OP_SUB")))
                else:
                    self.assertEqual(chosen, source)

                prefix = b"unrelated stack item"
                for values, accepted in (((8, 3, 1, 5), True), ((8, 3, 0, 5), False), ((8, 3, 1, 4), False)):
                    stack = [prefix, *map(encode_num, (values[order.index(index)] for index in range(4)))]
                    for script in (source, chosen):
                        if accepted:
                            self.assertEqual(evaluate(script, stack), ([prefix], []))
                        else:
                            with self.assertRaises(ScriptError):
                                evaluate(script, stack)

    def test_packet_slices_use_the_unread_suffix(self):
        prefix, packet = b"caller", b"ab--cdxyz"
        for chronicle in (False, True):
            graph = Graph(1)
            value, = graph.inputs
            checks = []
            for offset, expected in ((0, b"AB"), (4, b"CD"), (6, b"XY")):
                decoded = graph.packet_slice(value, offset, 2, decode=push(b"  ") + asm("OP_XOR"),
                                             chronicle=chronicle)
                literal = graph.define(push(expected))
                checks.append(graph.define(asm("OP_EQUAL"), (decoded, literal)))
            baseline = graph.emit_assertions(checks)
            compact = graph.emit_assertions(checks, compact=True, reorder=True)
            self.assertLess(len(compact), len(baseline))

            def observe(main, alt):
                self.assertLessEqual(main.count(packet) + alt.count(packet), 1)

            self.assertEqual(evaluate(compact, [prefix, packet], observe_stack=observe), ([prefix], []))
            for malformed in (packet[:7], b"ab--zzxyz"):
                for script in (baseline, compact):
                    with self.assertRaises(ScriptError):
                        evaluate(script, [prefix, malformed])

    def test_packet_slices_keep_random_access_for_other_uses(self):
        for offsets, check_packet in (((2, 0), False), ((0, 1), False), ((0, 2), True)):
            with self.subTest(offsets=offsets, check_packet=check_packet):
                graph = Graph(1)
                packet, = graph.inputs
                chunks = [graph.packet_slice(packet, offset, 2) for offset in offsets]
                checks = [graph.define(asm("OP_EQUAL"), tuple(chunks))]
                if check_packet:
                    literal = graph.define(push(b"aaaa"))
                    checks.append(graph.define(asm("OP_EQUAL"), (packet, literal)))
                plain = graph.emit_assertions(checks, compact=True)
                graph.packet_reads.clear()
                self.assertEqual(plain, graph.emit_assertions(checks, compact=True))
                self.assertEqual(evaluate(plain, [b"aaaa"]), ([], []))

    def test_residue_block_defers_polynomial_remainders(self):
        graph = Graph(2)
        left, right = graph.inputs
        block = graph.residue_block(5)
        divisor = block.integer(5)
        baseline = graph.remainder(graph.define(asm("OP_ADD"), (graph.remainder(left, divisor),
                                                                 graph.remainder(right, divisor))), divisor)
        operands = (block.remainder(left, divisor), block.remainder(right, divisor))
        value = block.define(asm("OP_ADD"), operands)
        reduced = graph.remainder(value, divisor, reuse=True)
        self.assertEqual(graph.remainder(reduced, divisor, reuse=True), reduced)
        start = list(map(encode_num, (12, -9)))
        eager, _ = evaluate(graph.emit((baseline,)), start)
        deferred, _ = evaluate(graph.emit((reduced,)), start)
        self.assertEqual(tuple(map(decode_num, eager + deferred)), (-2, 3))
        self.assertEqual(decode_num(eager[0]) % 5, decode_num(deferred[0]) % 5)

    def test_residue_block_rejects_operations_that_observe_representatives(self):
        graph = Graph(1)
        value, = graph.inputs
        with self.assertRaisesRegex(ValueError, "positive integer modulus"):
            graph.residue_block(0)
        block = graph.residue_block(5)
        with self.assertRaisesRegex(ValueError, "polynomial arithmetic"):
            block.define(asm("OP_0NOTEQUAL"), (value,))
        with self.assertRaisesRegex(ValueError, "declared modulus"):
            block.remainder(value, block.integer(7))

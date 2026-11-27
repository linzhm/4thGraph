"""Cross-backend checks for Script graph lowering."""

import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num
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

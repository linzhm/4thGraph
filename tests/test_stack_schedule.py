"""Cross-backend checks for Script graph lowering."""

import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, encode_num
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

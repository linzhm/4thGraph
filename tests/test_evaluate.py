"""Regression checks for the development evaluator's stack operations."""

import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm


STACK_OPERATIONS = (
    ('OP_SWAP', (b'a', b'b'), (b'b', b'a')),
    ('OP_2DUP', (b'a', b'b'), (b'a', b'b', b'a', b'b')),
    ('OP_3DUP', (b'a', b'b', b'c'), (b'a', b'b', b'c', b'a', b'b', b'c')),
    ('OP_TUCK', (b'a', b'b'), (b'b', b'a', b'b')),
    ('OP_2SWAP', (b'a', b'b', b'c', b'd'), (b'c', b'd', b'a', b'b')),
)


class StackOperationTests(unittest.TestCase):
    def test_reject_every_insufficient_stack_depth(self):
        for opcode, operands, _ in STACK_OPERATIONS:
            program = asm(opcode)
            for depth in range(len(operands)):
                with self.subTest(opcode=opcode, depth=depth):
                    with self.assertRaisesRegex(ScriptError, r'stack underflow at byte 0'):
                        evaluate(program, operands[:depth])

    def test_preserve_stack_order_with_enough_operands(self):
        for opcode, operands, expected in STACK_OPERATIONS:
            program = asm(opcode)
            for prefix in ((), (b'prefix',)):
                with self.subTest(opcode=opcode, prefix=prefix):
                    stack, alt = evaluate(program, prefix + operands)
                    self.assertEqual(stack, list(prefix + expected))
                    self.assertEqual(alt, [])

    def test_skipped_stack_operations_do_not_require_operands(self):
        for opcode, _, _ in STACK_OPERATIONS:
            with self.subTest(opcode=opcode):
                self.assertEqual(evaluate(asm(f'OP_0 OP_IF {opcode} OP_ENDIF')), ([], []))

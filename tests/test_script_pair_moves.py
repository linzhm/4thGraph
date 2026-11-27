"""Regression checks for paired Script moves and shared instruction parsing."""

import unittest

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, encode_num, push, without_codeseparators
from fourthgraph.compiler.stack_schedule import compact_pair_moves


class ScriptPairMoveTests(unittest.TestCase):
    def test_pair_moves_compact_copy_and_rotations_without_editing_push_data(self):
        for source, target in (("3 OP_PICK 3 OP_PICK", "OP_2OVER"),
                               ("3 OP_ROLL 3 OP_ROLL", "OP_2SWAP"),
                               ("5 OP_ROLL 5 OP_ROLL", "OP_2ROT")):
            with self.subTest(source=source):
                raw = asm(source)
                data = push(raw * 80)
                stack = list(map(encode_num, range(8)))
                self.assertEqual(compact_pair_moves(data + raw), data + asm(target))
                self.assertEqual(evaluate(compact_pair_moves(raw), stack), evaluate(raw, stack))
        self.assertEqual(compact_pair_moves(asm("3 OP_PICK 4 OP_PICK")), asm("3 OP_PICK 4 OP_PICK"))

    def test_separator_filter_preserves_complete_pushes(self):
        separator = asm("OP_CODESEPARATOR")
        for width in (1, 76, 256, 65_536):
            with self.subTest(width=width):
                data = push(separator * width)
                self.assertEqual(without_codeseparators(separator + data + separator), data)
        with self.assertRaisesRegex(ValueError, "truncated Script push payload"):
            without_codeseparators(push(separator * 76)[:-1])

"""Regression checks for literal-depth Script stack rewrites."""

import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, push
from fourthgraph.compiler.stack_peephole import compact_stack_moves


class StackPeepholeTests(unittest.TestCase):
    def test_stack_peepholes_preserve_values_and_minimum_depth(self):
        pairs = [
            ("3 OP_PICK 3 OP_PICK", "OP_2OVER", 4),
            ("OP_DROP OP_DROP", "OP_2DROP", 2),
            ("OP_OVER OP_OVER", "OP_2DUP", 2),
            ("OP_SWAP OP_OVER", "OP_TUCK", 2),
            ("OP_SWAP OP_ROT OP_SWAP", "OP_ROT OP_ROT", 3),
            ("2 OP_PICK 2 OP_PICK", "OP_3DUP OP_DROP", 3),
            ("OP_DROP 20 OP_ROLL OP_DROP", "21 OP_ROLL OP_2DROP", 22),
            ("3 OP_ROLL OP_DROP OP_ROT OP_DROP", "OP_2SWAP OP_2DROP", 4),
            ("5 OP_ROLL OP_DROP 4 OP_ROLL OP_DROP", "OP_2ROT OP_2DROP", 6),
            ("OP_DROP 127 OP_ROLL OP_DROP", "OP_DROP 127 OP_ROLL OP_DROP", 129),
            ("127 OP_ROLL OP_DROP 128 OP_ROLL OP_DROP", "127 OP_ROLL 129 OP_ROLL OP_2DROP", 130),
            ("20 OP_ROLL OP_ROT OP_SWAP", "OP_SWAP 20 OP_ROLL", 21),
            ("4 OP_PICK OP_2ROT OP_2ROT OP_2ROT", "4 OP_PICK", 5),
            ("OP_2ROT OP_2ROT OP_2ROT 5 OP_PICK", "5 OP_PICK", 6),
            ("3 OP_PICK OP_2ROT OP_2ROT OP_2ROT", "3 OP_PICK OP_2ROT OP_2ROT OP_2ROT", 5),
            ("OP_2ROT OP_2ROT OP_2ROT 4 OP_PICK", "OP_2ROT OP_2ROT OP_2ROT 4 OP_PICK", 6),
        ]
        for source, target, depth in pairs:
            with self.subTest(source=source):
                raw = asm(source)
                compact = compact_stack_moves(raw)
                self.assertEqual(compact, asm(target))
                stack = [bytes([n]) for n in range(depth + 3)]
                for height in (depth - 1, depth, depth + 3):
                    if height < depth:
                        for script in (raw, compact):
                            with self.assertRaises(ScriptError):
                                evaluate(script, stack[:height])
                    else:
                        self.assertEqual(evaluate(raw, stack[:height]), evaluate(compact, stack[:height]))

    def test_stack_peepholes_preserve_embedded_pushes_and_branch_boundaries(self):
        raw = asm("2 OP_PICK 2 OP_PICK")
        data = push(raw * 80)
        branch = asm("OP_IF OP_DROP OP_ELSE OP_DROP OP_ENDIF")
        nonminimal = asm("OP_DROP 0x0200 OP_ROLL OP_DROP")
        self.assertEqual(compact_stack_moves(data + branch + nonminimal), data + branch + nonminimal)

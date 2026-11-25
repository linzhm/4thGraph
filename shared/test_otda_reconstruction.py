"""Check shared fixed-output dictionaries against signed output ordering."""
import unittest

from shared.evaluate import evaluate
from shared.otda_reconstruction import Reconstruction, reconstruct_mixed
from shared.script import push
from shared.transaction import Output, compact


def pattern(parts, widths):
    return Reconstruction(b"".join(push(p) for p in parts), parts, widths)


class MixedReconstructionTests(unittest.TestCase):
    def test_multiple_dictionaries_recreate_exact_signed_outputs(self):
        left = pattern((b"A" * 500, b"B" * 500), (2,))
        right = pattern((b"C" * 500, b"D" * 500, b"E" * 500), (1, 2))
        one = Output(20, b"A" * 500 + b"ab" + b"B" * 500)
        two = Output(30, b"C" * 500 + b"c" + b"D" * 500 + b"de" + b"E" * 500)
        literal = Output(40, b"\x51")
        outputs = (two, literal, one, two, one)
        prefix = b"signed prefix" + compact(len(outputs))
        suffix = bytes(8)
        preimage = prefix + b"".join(output.serialize() for output in outputs) + suffix
        program = reconstruct_mixed(preimage, outputs, (left, right))
        self.assertEqual(evaluate(program), ([preimage], []))
        self.assertLess(len(program), min(len(p.build(preimage, outputs)) for p in (left, right)))
        with self.assertRaisesRegex(ValueError, "differ from the signing preimage"):
            reconstruct_mixed(preimage, tuple(reversed(outputs)), (left, right))
        self.assertIsNone(reconstruct_mixed(preimage, (one, literal), (left, right)))

"""Check shared fixed-output dictionaries against signed output ordering."""
from dataclasses import replace
import unittest

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.otda_reconstruction import Reconstruction, push_repeated_bytes, reconstruct_mixed, shorter_reconstruction
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Output, compact


def pattern(parts, widths):
    return Reconstruction(b"".join(push(p) for p in parts), parts, widths)


class MixedReconstructionTests(unittest.TestCase):
    def test_repeated_byte_constructor_retains_the_exact_length_and_stack(self):
        block = bytes(range(32))
        for count in (8, 63, 64, 256):
            with self.subTest(count=count):
                data = b"prefix" + block * count + b"tail"
                constructor = push_repeated_bytes(data)
                self.assertLess(len(constructor), len(push(data)))
                self.assertEqual(evaluate(constructor, [b"outer"]), ([b"outer", data], []))
        for data in (b"", block, block * 2):
            self.assertEqual(push_repeated_bytes(data), push(data))

    def test_constructor_must_beat_the_literal_encoding(self):
        template = pattern((b"A" * 100, b"B" * 100), (2,))
        output = Output(100, b"A" * 100 + b"ab" + b"B" * 100)
        preimage = b"prefix" + output.serialize() + bytes(8)
        self.assertIsNone(shorter_reconstruction(preimage, (output,), (template,)))
        repeated = b"prefix" + output.serialize() * 2 + bytes(8)
        constructor = shorter_reconstruction(repeated, (output, output), (template,))
        self.assertEqual(evaluate(constructor), ([repeated], []))

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

    def test_preserves_output_framing_at_compact_size_boundaries(self):
        trailer = bytes.fromhex("7856341261000000")
        for size, header in ((252, "fc"), (253, "fdfd00"), (65535, "fdffff"), (65536, "fe00000100")):
            with self.subTest(script_bytes=size):
                left = pattern((b"A", b"B" * (size - 2)), (1,))
                right = pattern((b"C", b"D" * (size - 2)), (1,))
                first = Output(0, b"A\xff" + left.fixed_parts[-1])
                second = Output(2_100_000_000_000_000, b"C\x00" + right.fixed_parts[-1])
                # Literal outputs sit on both sides of recognized outputs.
                literal = Output(17, b"\x51" * 253)
                outputs = (literal, second, first, literal)
                script_length = bytes.fromhex(header)
                self.assertEqual(first.serialize()[8:8 + len(script_length)], script_length)
                prefix = b"\x02\x00\x00\x00" + compact(len(outputs))
                preimage = prefix + b"".join(out.serialize() for out in outputs) + trailer
                for program in (left.build(preimage, outputs), reconstruct_mixed(preimage, outputs, (left, right))):
                    self.assertEqual(evaluate(program, stack=[b"sentinel"]), ([b"sentinel", preimage], []))

                wrong_amount = (literal, replace(second, value=second.value - 1), first, literal)
                with self.assertRaisesRegex(ValueError, "differ from the signing preimage"):
                    reconstruct_mixed(preimage, wrong_amount, (left, right))

    def test_preserves_output_count_at_compact_size_boundary(self):
        left = pattern((b"A", b"B"), (1,))
        right = pattern((b"C", b"D"), (1,))
        for size, count in ((252, b"\xfc"), (253, b"\xfd\xfd\x00")):
            with self.subTest(output_count=size):
                outputs = (Output(1, b"AxB"),) + (Output(2, b"\x51"),) * (size - 2) + (Output(3, b"CyD"),)
                preimage = b"signed inputs" + count + b"".join(out.serialize() for out in outputs) + bytes(8)
                self.assertEqual(evaluate(reconstruct_mixed(preimage, outputs, (left, right))), ([preimage], []))

    def test_mismatched_fixed_byte_is_copied_literally(self):
        left = pattern((b"A", b"B"), (1,))
        right = pattern((b"C", b"D"), (1,))
        first, second, nonmatching = Output(20, b"AxB"), Output(30, b"CyD"), Output(40, b"AxC")
        outputs = (first, nonmatching, second)
        preimage = b"prefix" + b"".join(out.serialize() for out in outputs) + bytes(8)
        self.assertIsNone(left.match(nonmatching.script))
        self.assertEqual(evaluate(reconstruct_mixed(preimage, outputs, (left, right))), ([preimage], []))

"""Verify the scaled secp256k1 kernels against an affine group-law reference."""

import os
from random import Random
import unittest

from fourthgraph.benchmark.validation import Node
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, number, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.script_builder import ScriptBuilder


FIELD = (1 << 256) - (1 << 32) - 977
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
ALT_MARKER = b"outer stack"
SAVE_ALT = push(ALT_MARKER) + asm("OP_TOALTSTACK")


def affine_add(left, right):
    """Independent affine addition on the original secp256k1 curve."""
    if left is None or right is None:
        return right if left is None else left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % FIELD == 0:
            return None
        slope = 3 * x1 * x1 * pow(2 * y1, -1, FIELD) % FIELD
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, FIELD) % FIELD
    x = (slope * slope - x1 - x2) % FIELD
    return x, (slope * (x1 - x) - y1) % FIELD


def generator_multiple(scalar):
    point, bit = None, GENERATOR
    for digit in reversed(bin(scalar % ORDER)[2:]):
        if digit == "1":
            point = affine_add(point, bit)
        bit = affine_add(bit, bit)
    return point


class Secp256k1LibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = ScriptBuilder("REQUIRE stdlib/secp256k1.fth\n")
        (root,), _ = evaluate(cls.app.emit("secp256k1-scale-root", b""))
        cls.root = decode_num(root)
        cls.x_scale = pow(cls.root, 2, FIELD)
        cls.y_scale = pow(cls.root, 3, FIELD)
        rng = Random(256)
        scalars = (1, 2, 3, 7, ORDER - 1, ORDER // 2, *(rng.randrange(1, ORDER) for _ in range(12)))
        cls.points = [generator_multiple(scalar) for scalar in scalars]

    def scale(self, point):
        x, y = point
        return x * self.x_scale % FIELD, y * self.y_scale % FIELD

    def project(self, point, z):
        if point is None:
            return 0, z, 0
        x, y = self.scale(point)
        return x * z % FIELD, y * z % FIELD, z

    def check_point(self, output, expected):
        x, y, z = (decode_num(item) % FIELD for item in output)
        if expected is None:
            self.assertEqual((x, z), (0, 0))
            self.assertNotEqual(y, 0)
        else:
            self.assertNotEqual(z, 0)
            inverse = pow(z, -1, FIELD)
            self.assertEqual((x * inverse % FIELD, y * inverse % FIELD), self.scale(expected))

    def check_kernel(self, code, prefix, coordinates, expected):
        stack = [encode_num(value) for value in (*prefix, *coordinates)]
        output, alt = evaluate(SAVE_ALT + code, stack)
        self.assertEqual(output[:-3], stack[:len(prefix)])
        self.assertEqual(alt, [ALT_MARKER])
        self.check_point(output[-3:], expected)
        return output

    def test_shared_coordinate_scaling(self):
        self.assertEqual(21 * pow(self.root, 6, FIELD) % FIELD, 1)
        self.assertIn("secp256k1-scale-affine-pair", self.app.imported_words)
        code = self.app.emit("secp256k1-scale-affine-pair", b"")
        prefix = [encode_num(FIELD), b"keep"]
        for left, right in zip(self.points, reversed(self.points), strict=True):
            stack = prefix + [encode_num(value) for value in (*left, *right)]
            output, alt = evaluate(SAVE_ALT + code, stack)
            self.assertEqual((output[:2], alt), (prefix, [ALT_MARKER]))
            coordinates = [decode_num(item) for item in output[2:]]
            self.assertEqual(coordinates, [*self.scale(left), *self.scale(right)])
            for x, y in zip(coordinates[::2], coordinates[1::2], strict=True):
                self.assertEqual((3 * y * y - 3 * x * x * x) % FIELD, 1)

    def test_complete_scaled_additions(self):
        point, inverse = self.points[0], self.points[4]
        cases = [(None, None), (None, point), (point, None), (point, inverse), (point, point)]
        cases.extend(zip(self.points, reversed(self.points), strict=True))
        for placement, prefix in ((0, (FIELD, -19)), (1, (-19, FIELD))):
            projective = self.app.emit("secp256k1-scaled-add-with-field", b"", placement)
            affine = self.app.emit("secp256k1-scaled-add-affine-with-field", b"", placement)
            for index, (left, right) in enumerate(cases):
                with self.subTest(placement=placement, case=index):
                    expected = affine_add(left, right)
                    lhs = self.project(left, -17)
                    self.check_kernel(projective, prefix, (*lhs, *self.project(right, 23)), expected)
                    if right is not None:
                        self.check_kernel(affine, prefix, (*lhs, *self.scale(right)), expected)

    def test_scaled_doubling_and_paired_doubling(self):
        for placement, prefix in ((0, (FIELD, -19)), (1, (-19, FIELD))):
            single = self.app.emit("secp256k1-scaled-double-with-field", b"", placement)
            pair = self.app.emit("secp256k1-scaled-double-pair-with-field", b"", placement)
            for index, point in enumerate((None, *self.points)):
                with self.subTest(placement=placement, case=index):
                    coordinates = self.project(point, -17)
                    twice = affine_add(point, point)
                    four = affine_add(twice, twice)
                    self.check_kernel(single, prefix, coordinates, twice)
                    self.check_kernel(single + single, prefix, coordinates, four)
                    self.check_kernel(pair, prefix, coordinates, four)

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires tools/verify_node.sh")
    def test_scaled_library_scripts_in_both_engines(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
        left, right = self.points[:2]
        point = self.project(left, -17)
        infinity = self.project(None, -17)
        inverse = self.points[4]
        double = affine_add(left, left)
        cases = (
            ("secp256k1-scaled-add-with-field", (*point, *self.project(right, 23)), affine_add(left, right)),
            ("secp256k1-scaled-add-with-field", (*point, *self.project(inverse, 23)), None),
            ("secp256k1-scaled-add-affine-with-field", (*point, *self.scale(right)), affine_add(left, right)),
            ("secp256k1-scaled-add-affine-with-field", (*infinity, *self.scale(right)), right),
            ("secp256k1-scaled-double-with-field", point, double),
            ("secp256k1-scaled-double-pair-with-field", point, affine_add(double, double)),
            ("secp256k1-scaled-double-pair-with-field", infinity, None),
        )
        contexts = (
            (1, activation - 1, activation - 1),
            (2, activation - 1, activation + 1),
            (2, activation, activation + 1),
        )
        cleanup = asm("OP_FROMALTSTACK") + push(ALT_MARKER) + asm("OP_EQUALVERIFY OP_1")
        for word, coordinates, expected in cases:
            for placement, prefix in ((0, (FIELD, -19)), (1, (-19, FIELD))):
                code = self.app.emit(word, b"", placement)
                output = self.check_kernel(code, prefix, coordinates, expected)
                for version, funding_height, spend_height in contexts:
                    context = dict(spend_height=spend_height, activation_height=activation,
                                   utxo_heights=(funding_height,))
                    for valid in (True, False):
                        with self.subTest(word=word, placement=placement, version=version,
                                          funding_height=funding_height, valid=valid):
                            values = list(map(decode_num, output))
                            if not valid:
                                values[-1] += 1
                            assertions = b"".join(number(value) + asm("OP_EQUALVERIFY")
                                                  for value in reversed(values))
                            lock = SAVE_ALT + code + assertions + cleanup
                            parent = Transaction((Input(bytes([42]) * 32, 0),), (Output(1000, lock),))
                            witness = b"".join(number(value) for value in (*prefix, *coordinates))
                            spend = Transaction((Input(parent.txid_wire(), 0, script=witness),),
                                                (Output(900, asm("OP_1")),), version=version)
                            self.assertEqual(node.verdicts(spend, (parent,), **context), [valid])
                            if valid:
                                validate_at_heights(spend, (parent,), **context)
                            else:
                                with self.assertRaises((ValueError, RuntimeError)):
                                    validate_at_heights(spend, (parent,), **context)

"""Verify the shared secp256k1 kernels against independent arithmetic references."""

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
LATTICE_A = 0x3086D221A7D46BCDE86C90E49284EB15
LATTICE_B = 0xE4437ED6010E88286F547FA90ABFE4C3
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


def split_scalar(scalar):
    half = ORDER // 2
    first = (scalar * LATTICE_A + half) // ORDER
    second = (scalar * LATTICE_B + half) // ORDER
    return (scalar - LATTICE_A * first - (LATTICE_A + LATTICE_B) * second,
            LATTICE_B * first - LATTICE_A * second)


def rounding_transition(coefficient, quotient):
    return (quotient * ORDER - ORDER // 2 + coefficient - 1) // coefficient


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

    def test_glv_split_rounding_and_magnitude_bounds(self):
        self.assertEqual(LATTICE_A ** 2 + LATTICE_A * LATTICE_B + LATTICE_B ** 2, ORDER)
        self.assertLess(2 * LATTICE_A + LATTICE_B, 1 << 129)
        rng = Random(160)
        scalars = {0, 1, ORDER // 2, ORDER - 1, ORDER, *(rng.randrange(ORDER) for _ in range(128))}
        for coefficient in (LATTICE_A, LATTICE_B):
            for quotient in (1, 2, coefficient // 2, coefficient - 1, coefficient):
                boundary = rounding_transition(coefficient, quotient)
                scalars.update(range(boundary - 1, boundary + 2))
        for word, extra in (("secp256k1-lambda-split", ()),
                            ("secp256k1-lambda-split-with-order", (ORDER,))):
            code = self.app.emit(word, b"")
            for scalar in sorted(scalars):
                with self.subTest(word=word, scalar=scalar):
                    expected = split_scalar(scalar)
                    self.assertTrue(all(abs(component) < 1 << 128 for component in expected))
                    stack = [encode_num(value) for value in (-19, scalar, *extra)]
                    result, alt = evaluate(SAVE_ALT + code, stack)
                    self.assertEqual((list(map(decode_num, result)), alt), ([-19, *expected], [ALT_MARKER]))

    def check_script_in_both_engines(self, label, node, code, inputs, expected):
        activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
        contexts = (
            (1, activation - 1, activation - 1),
            (2, activation - 1, activation + 1),
            (2, activation, activation + 1),
        )
        witness = b"".join(number(value) for value in inputs)
        cleanup = asm("OP_FROMALTSTACK") + push(ALT_MARKER) + asm("OP_EQUALVERIFY OP_1")
        for version, funding_height, spend_height in contexts:
            context = dict(spend_height=spend_height, activation_height=activation,
                           utxo_heights=(funding_height,))
            for valid in (True, False):
                with self.subTest(case=label, version=version, funding_height=funding_height, valid=valid):
                    values = [*expected[:-1], expected[-1] + int(not valid)]
                    assertions = b"".join(number(value) + asm("OP_EQUALVERIFY") for value in reversed(values))
                    lock = SAVE_ALT + code + assertions + cleanup
                    parent = Transaction((Input(bytes([42]) * 32, 0),), (Output(1000, lock),))
                    spend = Transaction((Input(parent.txid_wire(), 0, script=witness),),
                                        (Output(900, asm("OP_1")),), version=version)
                    self.assertEqual(node.verdicts(spend, (parent,), **context), [valid])
                    if valid:
                        validate_at_heights(spend, (parent,), **context)
                    else:
                        with self.assertRaises((ValueError, RuntimeError)):
                            validate_at_heights(spend, (parent,), **context)

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires tools/verify_node.sh")
    def test_glv_split_in_both_engines(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        a = rounding_transition(LATTICE_A, 1)
        b = rounding_transition(LATTICE_B, 1)
        for word, extra in (("secp256k1-lambda-split", ()),
                            ("secp256k1-lambda-split-with-order", (ORDER,))):
            code = self.app.emit(word, b"")
            for scalar in (0, ORDER, ORDER - 1, ORDER // 2, a - 1, a, b - 1, b):
                self.check_script_in_both_engines(
                    (word, scalar), node, code, (-19, scalar, *extra), (-19, *split_scalar(scalar)),
                )

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires tools/verify_node.sh")
    def test_scaled_library_scripts_in_both_engines(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
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
        for word, coordinates, expected in cases:
            for placement, prefix in ((0, (FIELD, -19)), (1, (-19, FIELD))):
                code = self.app.emit(word, b"", placement)
                output = self.check_kernel(code, prefix, coordinates, expected)
                self.check_script_in_both_engines(
                    (word, placement, coordinates), node, code, (*prefix, *coordinates),
                    tuple(map(decode_num, output)),
                )

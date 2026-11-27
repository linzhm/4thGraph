"""Exercise the runtime stack contracts of the bundled Script builders."""

import os
from random import Random
import unittest

from fourthgraph.benchmark.validation import Node, chain_verdict
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.source import CompileError


PREFIX = push(b"prefix")
ALT_SENTINEL = push(b"outer") + asm("OP_TOALTSTACK")
FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def affine_add(left, right):
    """Independent affine group law for validating homogeneous Script outputs."""
    if left is None or right is None:
        return right if left is None else left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % FIELD == 0:
        return None
    numerator, denominator = (3 * x1 * x1, 2 * y1) if left == right else (y2 - y1, x2 - x1)
    slope = numerator * pow(denominator, -1, FIELD) % FIELD
    x = (slope * slope - x1 - x2) % FIELD
    return x, (slope * (x1 - x) - y1) % FIELD


def projective(point, scale):
    if point is None:
        return (0, scale, 0)
    x, y = point
    return x * scale % FIELD, y * scale % FIELD, scale


class ScriptFragmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = ScriptBuilder("REQUIRE stdlib/script-fragments.fth\n")

    def test_reversal_and_big_endian_decoding_preserve_surrounding_stack(self):
        random = Random(340)
        values = (bytes(32), bytes(range(32)), b"\x80" + bytes(31), b"\xff" * 32,
                  *(random.randbytes(32) for _ in range(64)))
        for word, expected in (
            ("script-reverse32", lambda value: value[::-1]),
            ("script-uint256be", lambda value: encode_num(int.from_bytes(value, "big"))),
        ):
            script = self.builder.emit(word, PREFIX)
            self.assertTrue(script.startswith(PREFIX))
            for value in values:
                with self.subTest(word=word, value=value.hex()):
                    code = ALT_SENTINEL + script[len(PREFIX):]
                    self.assertEqual(evaluate(code, [b"keep", value]), ([b"keep", expected(value)], [b"outer"]))

    def test_pick_and_save_preserve_operand_order_and_fail_on_missing_depth(self):
        stack = [bytes([value]) for value in range(1, 20)]
        for depth in (0, 1, 2, 17):
            for word in ("script-pick-depth", "script-save-depth"):
                with self.subTest(word=word, depth=depth):
                    code = ALT_SENTINEL + self.builder.emit(word, b"", depth)
                    selected = stack[-1 - depth]
                    expected = ((stack + [selected], [b"outer"]) if word == "script-pick-depth"
                                else (stack, [b"outer", selected]))
                    self.assertEqual(evaluate(code, stack), expected)
                    with self.assertRaises(ScriptError):
                        evaluate(code, stack[:depth])

    def test_drop_and_restore_counts_preserve_other_items(self):
        items = [b"one", b"two", b"three", b"four"]
        save = b"".join(push(item) + asm("OP_TOALTSTACK") for item in items)
        for count in (0, 1, 2):
            with self.subTest(count=count):
                drop = self.builder.emit("script-drop-pairs", b"", count)
                restore = self.builder.emit("script-restore-items", b"", count)
                self.assertEqual(evaluate(ALT_SENTINEL + drop, [b"keep", *items]),
                                 ([b"keep", *items[:4 - 2 * count]], [b"outer"]))
                self.assertEqual(evaluate(ALT_SENTINEL + save + restore, [b"keep"]),
                                 ([b"keep", *items[::-1][:count]], [b"outer", *items[:4 - count]]))
        for word in ("script-drop-pairs", "script-restore-items"):
            with self.assertRaises(ScriptError):
                evaluate(self.builder.emit(word, b"", 1))
            for count in (-1, 257):
                with self.subTest(word=word, count=count), self.assertRaises(CompileError):
                    self.builder.emit(word, b"", count)

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires tools/verify_node.sh")
    def test_composed_fragments_accept_and_reject_complete_spends(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        data = bytes(range(32))
        app = ScriptBuilder("""
            REQUIRE stdlib/script-fragments.fth
            : reverse-and-keep ( script -- script )
                0 script-save-depth script-reverse32 1 script-restore-items ;
        """)
        lock = app.emit("reverse-and-keep", b"") + push(data) + asm("OP_EQUALVERIFY")
        lock += push(data[::-1]) + asm("OP_EQUAL")
        parent = Transaction((Input(bytes([7]) * 32, 0),), (Output(1000, lock),))
        tx = Transaction((Input(parent.txid_wire(), 0),), (Output(900, asm("OP_1")),))
        for witness, expected in ((data, True), (data[::-1], False), (data[:-1], False)):
            with self.subTest(witness=witness.hex()):
                spend = tx.with_script(0, push(witness))
                self.assertIs(chain_verdict(spend, (parent,)), expected)
                self.assertEqual(node.verdicts(spend, (parent,)), [expected])


class Secp256k1LibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = ScriptBuilder("REQUIRE stdlib/secp256k1.fth\n")

    def test_public_constants_append_to_the_supplied_script(self):
        for name, expected in zip(("field", "order", "gx", "gy"), (FIELD, ORDER, *GENERATOR), strict=True):
            with self.subTest(name=name):
                code = self.builder.emit(f"secp256k1-{name}", PREFIX)
                self.assertTrue(code.startswith(PREFIX))
                self.assertEqual(evaluate(code), ([b"prefix", encode_num(expected)], []))

    def test_point_operations_preserve_stack_and_match_affine_group_law(self):
        twice = affine_add(GENERATOR, GENERATOR)
        opposite = (GENERATOR[0], FIELD - GENERATOR[1])
        pairs = ((None, None), (None, GENERATOR), (GENERATOR, None), (GENERATOR, GENERATOR),
                 (GENERATOR, opposite), (GENERATOR, twice), (twice, GENERATOR))
        for left, right in pairs:
            p = projective(left, 3)
            q = projective(right, FIELD - 1)
            expected = affine_add(left, right)
            self.assert_point("add", (*p, *q), expected)
            if right is not None:
                self.assert_point("add-affine", (*p, *right), expected)
        for point in (None, GENERATOR, opposite, twice):
            doubled = affine_add(point, point)
            self.assert_point("double", projective(point, 7), doubled)
            self.assert_point("double-pair", projective(point, 7), affine_add(doubled, doubled))

    def assert_point(self, word, inputs, expected):
        with self.subTest(word=word, inputs=inputs):
            code = ALT_SENTINEL + self.builder.emit(f"secp256k1-{word}", b"")
            prefix = [encode_num(FIELD), b"keep"]
            stack, alt = evaluate(code, [*prefix, *map(encode_num, inputs)])
            self.assertEqual(alt, [b"outer"])
            self.assertEqual(stack[:2], prefix)
            x, y, z = map(decode_num, stack[2:])
            self.assertEqual((x**3 - y*y*z + 7*z**3) % FIELD, 0)
            if expected is None:
                self.assertEqual((x % FIELD, z % FIELD), (0, 0))
                self.assertNotEqual(y % FIELD, 0)
            else:
                inverse = pow(z, -1, FIELD)
                self.assertEqual((x * inverse % FIELD, y * inverse % FIELD), expected)

    def test_scalar_split_preserves_signed_result_order(self):
        code = ALT_SENTINEL + self.builder.emit("secp256k1-lambda-split", b"")
        random = Random(340)
        scalars = (0, 1, 2**128 - 1, 2**128, ORDER // 2, ORDER - 1, ORDER,
                   *(random.randrange(ORDER) for _ in range(32)))
        for scalar in scalars:
            with self.subTest(scalar=scalar):
                stack, alt = evaluate(code, [b"keep", encode_num(scalar)])
                self.assertEqual((stack[0], alt), (b"keep", [b"outer"]))
                k1, k2 = map(decode_num, stack[1:])
                self.assertLess(max(abs(k1), abs(k2)), 2**128)
                self.assertEqual((k1 + LAMBDA * k2) % ORDER, scalar % ORDER)

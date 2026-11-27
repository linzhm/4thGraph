"""Test independently checked scalar multiplication and curve-specific eligibility."""
from functools import cache
import json
import os
from shutil import which
import subprocess
import sys
import unittest

from fourthgraph.benchmark.validation import Node, chain_verdict
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.curve_lowering import compile_fixed_generator, compile_joint_generator_point
from fourthgraph.compiler.curve_windows import CURVES, GLV_REFERENCE, JOINT_STRATEGIES, P256, SECP256K1, SM2, fixed_table, scalar_plans
from fourthgraph.compiler.lowering import DATAFLOW, compile_word
from fourthgraph.compiler.source import CompileError, SourceCompiler
from fourthgraph.stdlib.weierstrass import CoordinateScale


def affine(coords, field):
    x, y, z = (decode_num(item) % field for item in coords)
    if not z:
        if x or not y:
            raise AssertionError("invalid projective infinity")
        return None
    inverse = pow(z, -1, field)
    return x * inverse % field, y * inverse % field


CURVE_OIDS = {
    "secp256k1": bytes.fromhex("06052b8104000a"),
    "p256": bytes.fromhex("06082a8648ce3d030107"),
    "sm2": bytes.fromhex("06082a811ccf5501822d"),
}


@cache
def generator_multiple(curve, scalar):
    scalar %= curve.order
    if scalar == 0:
        return None
    # RFC 5915 ECPrivateKey with named parameters. Fixtures use public test scalars.
    oid = CURVE_OIDS[curve.name]
    key = b"\x02\x01\x01\x04\x20" + scalar.to_bytes(32, "big") + bytes((0xA0, len(oid))) + oid
    result = subprocess.run(("openssl", "ec", "-inform", "DER", "-pubout", "-conv_form", "uncompressed",
                             "-outform", "DER"), input=bytes((0x30, len(key))) + key,
                            check=True, capture_output=True)
    uncompressed = result.stdout[-65:]
    if len(uncompressed) != 65 or uncompressed[0] != 4:
        raise AssertionError("OpenSSL did not return an uncompressed point")
    return int.from_bytes(uncompressed[1:33], "big"), int.from_bytes(uncompressed[33:], "big")


class CurveWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixed = {curve.name: {mode: compile_fixed_generator(curve, mode)
                                  for mode in ("binary", "fixed-window-2", "fixed-window-4")}
                     for curve in CURVES.values()}
        cls.joint = {name: compile_joint_generator_point(SECP256K1, name) for name in JOINT_STRATEGIES}

    def test_coordinate_scale_library_for_registered_curves(self):
        source = SourceCompiler("REQUIRE stdlib/weierstrass.fth")
        bundles = [compile_word(source.words["weierstrass-scale"], mode).script
                   for mode in ("baseline", "safe", "stack")]
        for curve in CURVES.values():
            scale = CoordinateScale(curve.field, 2)
            a, b = scale.coefficients(curve.a, curve.b)
            x, y = scale.affine(curve.generator)
            self.assertEqual((y*y - x*x*x - a*x - b) % curve.field, 0)
            self.assertEqual(scale.affine((x, y), inverse=True), curve.generator)
            self.assertIsNone(scale.affine(None))
            for script in bundles:
                for z in (0, -7, 1):
                    # A nonzero signed homogeneous representative and projective infinity.
                    values = (0, 1, 0) if z == 0 else (*(coordinate * z % curve.field for coordinate in curve.generator), z)
                    prefix = [b"outer", encode_num(curve.field)]
                    saved = asm("17 OP_TOALTSTACK")
                    forward = [*prefix, *map(encode_num, (*values, *scale.factors()))]
                    result, alt = evaluate(saved + script, forward)
                    self.assertEqual((result[:2], alt), (prefix, [encode_num(17)]))
                    self.assertEqual(affine(result[2:], curve.field), None if not z else (x, y))
                    original, _ = evaluate(script, result + list(map(encode_num, scale.factors(inverse=True))))
                    self.assertEqual(affine(original[2:], curve.field), None if not z else curve.generator)
        a, b = SECP256K1.normalized_a0().coefficients(SECP256K1.a, SECP256K1.b)
        self.assertEqual((a, 3 * b % SECP256K1.field), (0, 1))
        self.assertEqual((P256.field - 1) % 6, 0)
        self.assertNotEqual(pow(3 * P256.b, (P256.field - 1) // 6, P256.field), 1)
        self.assertIsNone(P256.normalized_a0())

    @unittest.skipUnless(which("openssl"), "requires OpenSSL for independent point multiplication")
    def test_curve_registry_and_fixed_tables(self):
        for curve in CURVES.values():
            for width in (1, 2, 4):
                self.assertEqual(fixed_table(curve, window_bits=width),
                                 tuple(generator_multiple(curve, i) for i in range(1 << width)))
            self.assertEqual(fixed_table(curve, split_bits=128),
                             tuple(generator_multiple(curve, i + (1 << 128) * j)
                                   for j in range(4) for i in range(4)))
        beta, eigenvalue = SECP256K1.endomorphism
        x, y = generator_multiple(SECP256K1, 1)
        self.assertEqual(generator_multiple(SECP256K1, eigenvalue), (beta * x % SECP256K1.field, y))
        for curve in (P256, SM2):
            self.assertFalse(any(plan.eligible for plan in scalar_plans(curve, joint=True)))
            with self.assertRaisesRegex(ValueError, "requires secp256k1"):
                compile_joint_generator_point(curve)

    @unittest.skipUnless(which("openssl"), "requires OpenSSL for independent point multiplication")
    def test_fixed_generator_all_plans_match_independent_points(self):
        for curve in CURVES.values():
            for mode, build in self.fixed[curve.name].items():
                for n in (0, 1, 2, 3, 4, 15, 16, (1 << 127) - 1, 1 << 128, 1 << 254, curve.order - 1):
                    with self.subTest(curve=curve.name, mode=mode, scalar=n):
                        stack, alt = evaluate(build.script, [b"caller", encode_num(n)])
                        self.assertEqual((stack[0], alt), (b"caller", []))
                        self.assertEqual(affine(stack[1:], curve.field), generator_multiple(curve, n))
                for invalid in (encode_num(-1), encode_num(curve.order), b"\x01\x00"):
                    with self.assertRaises(ScriptError):
                        evaluate(build.script, [invalid])
            auto = compile_fixed_generator(curve)
            winner = min(self.fixed[curve.name].values(), key=lambda row: len(row.script))
            self.assertEqual((auto.selected, auto.script), (winner.selected, winner.script))

    @unittest.skipUnless(which("openssl"), "requires OpenSSL for independent point multiplication")
    def test_joint_glv_edges_and_input_guards(self):
        curve = SECP256K1
        x, y = generator_multiple(curve, 1)
        vectors = ((1, 0, 0), (1, 1, 0), (1, 0, curve.order), (curve.order - 1, 3, 3),
                   (5, (1 << 128) + 3, curve.order - 1), (17, curve.order - 1, (1 << 253) + 77),
                   (5, 123, curve.order // 2), (31, (1 << 127) - 1, curve.order // 7))
        for mode, build in self.joint.items():
            for point_n, s, k in vectors:
                with self.subTest(mode=mode, point_n=point_n, s=s, k=k):
                    public = generator_multiple(curve, point_n)
                    stack, alt = evaluate(asm("17 OP_TOALTSTACK") + build.script,
                                          [b"outer", *map(encode_num, (*public, s, k))])
                    self.assertEqual((stack[0], decode_num(stack[1]), alt), (b"outer", curve.field, [encode_num(17)]))
                    self.assertEqual(affine(stack[2:], curve.field), generator_multiple(curve, s + k * point_n))
            for values in ((0, 0, 1, 1), (curve.field, y, 1, 1), (x, y, 1, curve.order + 1)):
                with self.assertRaises(ScriptError):
                    evaluate(build.script, list(map(encode_num, values)))

    def test_cli_advertises_and_builds_registered_curves(self):
        command = (sys.executable, "-m", "fourthgraph.workflow.protocol")
        result = json.loads(subprocess.check_output((*command, "--capabilities")))
        capabilities = result["curve_multiply"]["curves"]
        self.assertEqual(set(capabilities), set(CURVES))
        self.assertEqual(capabilities["secp256k1"]["joint"], list(JOINT_STRATEGIES))
        self.assertEqual(capabilities["p256"]["joint"], [])
        self.assertEqual(capabilities["sm2"]["joint"], [])
        program = json.loads(subprocess.check_output((*command, "curve-multiply", "--curve", "p256",
                                                      "--strategy", "fixed-window-4")))
        self.assertEqual(program["script_hex"], self.fixed["p256"]["fixed-window-4"].script.hex())
        for optimization in ("baseline", "safe", "stack", DATAFLOW):
            options = {name: compile_joint_generator_point(SECP256K1, name, optimization=optimization)
                       for name in JOINT_STRATEGIES}
            program = json.loads(subprocess.check_output((*command, "curve-multiply", "--curve", "secp256k1",
                                                          "--operation", "joint", "--optimize", optimization)))
            winner = min(options, key=lambda name: len(options[name].script))
            self.assertEqual(program["selected"], winner)
            self.assertEqual(program["script_hex"], options[winner].script.hex())
        rejected = subprocess.run((*command, "curve-multiply", "--curve", "sm2", "--operation", "joint"),
                                  capture_output=True)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn(b"requires secp256k1", rejected.stderr)

    def test_declared_words_compose_and_preserve_input_checks(self):
        frontend = SourceCompiler("""
            curve-multiply: mul-p256 p256 generator auto ;
            curve-multiply: mul-joint secp256k1 joint glv-joint-window-2 ;
            curve-multiply: mul-auto secp256k1 joint auto ;
            : check-p256-scalar ( script-int -- cell )
                mul-p256 2drop drop 1
            ;
        """)
        expected_script = self.fixed["p256"]["fixed-window-4"].script
        self.assertEqual(compile_word(frontend.words["mul-p256"], "stack").script, expected_script)
        self.assertEqual(compile_word(frontend.words["mul-joint"], "stack").script, self.joint[GLV_REFERENCE].script)
        chosen = min(self.joint.values(), key=lambda build: len(build.script))
        self.assertEqual(compile_word(frontend.words["mul-auto"], "stack").script, chosen.script)
        for optimization in ("baseline", "safe", "stack"):
            code = compile_word(frontend.words["check-p256-scalar"], optimization).script
            self.assertEqual(evaluate(code, [b""])[0], [encode_num(1)])
            with self.assertRaises(ScriptError):
                evaluate(code, [encode_num(P256.order)])
        with self.assertRaisesRegex(CompileError, "unknown curve"):
            SourceCompiler("curve-multiply: unsupported unknown generator auto ;")
        with self.assertRaisesRegex(CompileError, "requires secp256k1"):
            SourceCompiler("curve-multiply: unsupported p256 joint auto ;")

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires tools/verify_node.sh")
    @unittest.skipUnless(which("openssl"), "requires OpenSSL for independent point multiplication")
    def test_compiled_points_and_bounds_in_both_engines(self):
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])

        def check_verdict(lock, witness, valid):
            parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),))
            tx = Transaction((Input(parent.txid_wire(), 0, witness),), (Output(9_900, asm("OP_1")),))
            self.assertEqual(chain_verdict(tx, (parent,)), valid)
            self.assertEqual(node.verdicts(tx, (parent,), timeout_us=100_000), [valid])

        jobs = [(build.script, (n,), curve, generator_multiple(curve, n))
                for curve in CURVES.values() for build in self.fixed[curve.name].values()
                for n in (0, 19, curve.order - 1)]
        curve = SECP256K1
        point = generator_multiple(curve, 7)
        jobs.extend((build.script, (*point, s, k), curve, generator_multiple(curve, s + 7*k))
                    for build in self.joint.values() for s, k in ((23, curve.order - 4), (7, curve.order - 1), (0, 0)))
        for script, values, curve, target in jobs:
            with self.subTest(curve=curve.name, script_bytes=len(script), values=values):
                witness = b"".join(push(encode_num(value)) for value in values)
                stack, _ = evaluate(script, list(map(encode_num, values)))
                self.assertEqual(affine(stack[-3:], curve.field), target)
                locks = {
                    True: stack,
                    False: [*stack[:-1], encode_num(decode_num(stack[-1]) + 1)],
                }
                for valid, cells in locks.items():
                    lock = script + b"".join(push(item) + asm("OP_EQUALVERIFY") for item in reversed(cells)) + asm("OP_1")
                    check_verdict(lock, witness, valid)

        for registered in CURVES.values():
            script = self.fixed[registered.name]["fixed-window-4"].script
            for bad in (encode_num(-1), encode_num(registered.order), b"\x01\x00"):
                check_verdict(script + asm("OP_2DROP OP_DROP OP_1"), push(bad), False)
        for build in self.joint.values():
            for bad in ((0, 0, 1, 1), (*point, 1, curve.order + 1)):
                witness = b"".join(push(encode_num(value)) for value in bad)
                check_verdict(build.script + asm("OP_2DROP OP_2DROP OP_1"), witness, False)

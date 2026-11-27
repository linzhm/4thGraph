"""Test independently checked scalar multiplication and curve-specific eligibility."""
from functools import cache
import json
import os
from pathlib import Path
from shutil import which
import subprocess
import sys
import unittest

from fourthgraph.benchmark.validation import Node, chain_verdict
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.curve_lowering import compile_fixed_generator, compile_joint_generator_point, joint_vocabulary, link_joint_word
from fourthgraph.compiler.curve_windows import CURVES, GLV_REFERENCE, GLV_SCALED, JOINT_STRATEGIES, P256, SECP256K1, SM2, fixed_table, scalar_plans
from fourthgraph.compiler.lowering import DATAFLOW, compile_word
from fourthgraph.compiler.modular_scale import lower_affine_pair_scale, lower_modular_scale, lower_scaled_residuals
from fourthgraph.compiler.script_builder import ScriptBuilder
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


class WeierstrassModelTests(unittest.TestCase):
    def test_model_and_schnorr_arithmetic_can_be_imported_together(self):
        source = (Path(__file__).resolve().parents[1] / "projects" / "p2pkh-schnorr"
                  / "experiments" / "high-level" / "window-verifier.fth")
        imports = ("REQUIRE stdlib/weierstrass-model.fth", "REQUIRE arithmetic.fth")
        for order in (imports, imports[::-1]):
            with self.subTest(order=order):
                builder = ScriptBuilder("\n".join(order), source_path=source)
                self.assertIn("weierstrass-scaled-residuals", builder.formulas)
                self.assertIn("add-points", builder.formulas)


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

    def test_root_and_precomputed_scales_emit_identical_signed_residues(self):
        source = SourceCompiler("REQUIRE stdlib/weierstrass.fth")
        for curve in CURVES.values():
            roots = (2, curve.field - 1, curve.field // 2)
            for name, coordinates in (("weierstrass-scale-affine", (-1, curve.field - 1)),
                                      ("weierstrass-scale", (1 - curve.field, -711, 3)),
                                      ("weierstrass-scale", (0, -1, 0))):
                powers = compile_word(source.words[name], DATAFLOW).script
                rooted = compile_word(source.words[name + "-root"], DATAFLOW).script
                inputs = [b"caller", *map(encode_num, (curve.field, *coordinates))]
                for root in roots:
                    scale = CoordinateScale(curve.field, root)
                    expected = evaluate(powers, [*inputs, *map(encode_num, scale.factors())])
                    self.assertEqual(evaluate(rooted, [*inputs, encode_num(root)]), expected)

    def test_modular_scale_selection_requires_an_intermediate_size_proof(self):
        model = SECP256K1.normalized_a0()
        options = {"affine": True, "scriptnum_bytes": 129}
        fallback = lower_modular_scale(model.field, model.root, DATAFLOW, **options)
        narrow = lower_modular_scale(model.field, model.root, DATAFLOW, affine=True,
                                     coordinate_bound=model.field - 1, scriptnum_bytes=65)
        self.assertEqual(fallback, narrow)
        optimized = lower_modular_scale(model.field, model.root, DATAFLOW, coordinate_bound=model.field - 1, **options)
        self.assertLess(len(optimized), len(fallback))
        for x, y in ((-19, model.field - 1), (0, 12), (-1, 0)):
            source = [b"caller", *map(encode_num, (model.field, x, y))]
            self.assertEqual(evaluate(optimized, source), evaluate(fallback, source))

    def test_affine_pair_map_matches_two_independent_scales(self):
        for curve in CURVES.values():
            field = curve.field
            root = field // 2
            first, second = curve.generator, (1 - field, -15)
            inputs = [b"caller", *map(encode_num, (field, *first, *second))]
            single = lower_modular_scale(field, root, DATAFLOW, affine=True,
                                         coordinate_bound=field - 1, scriptnum_bytes=129)
            for budget in (65, 129):
                code = lower_affine_pair_scale(field, root, DATAFLOW, coordinate_bound=field - 1, scriptnum_bytes=budget)
                output, alt = evaluate(code, inputs)
                left, _ = evaluate(single, inputs[1:4])
                right, _ = evaluate(single, [inputs[1], *inputs[4:]])
                self.assertEqual((output, alt), ([b"caller", *left, *right[1:]], []))

    def test_fused_residuals_preserve_modular_zero_tests(self):
        model = SECP256K1.normalized_a0()
        cases = ((7, 3, (2, -2, 4, -4, 1)),
                 (model.field, pow(model.root, -1, model.field), (-9, 7, -100, 120, -3)))
        with self.assertRaisesRegex(ValueError, "within the ScriptNum budget"):
            lower_scaled_residuals(model.field, model.root, DATAFLOW, coordinate_bound=model.field - 1, scriptnum_bytes=32)
        for field, root, values in cases:
            x_factor, y_factor = pow(root, 2, field), pow(root, 3, field)
            separate = lower_modular_scale(field, root, DATAFLOW, coordinate_bound=field - 1, scriptnum_bytes=129)
            known = (3 * x_factor % field, 5 * y_factor % field, 3, 5, 1)
            for budget in (65, 129):
                fused = lower_scaled_residuals(field, root, DATAFLOW, coordinate_bound=field - 1, scriptnum_bytes=budget)
                for rx, ry, x, y, z in (values, known, (0, 0, 0, 1, 0)):
                    result, alt = evaluate(fused, [b"caller", *map(encode_num, (rx, ry, field, x, y, z))])
                    mapped, _ = evaluate(separate, list(map(encode_num, (field, x, y, z))))
                    self.assertEqual((result[0], decode_num(result[1]), alt), (b"caller", z, []))
                    before = tuple((decode_num(v) - r * z) % field == 0 for v, r in zip(mapped[1:3], (rx, ry)))
                    after = tuple(decode_num(v) == 0 for v in result[2:])
                    self.assertEqual(before, after)

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

    def test_row_maps_preserve_signed_representatives(self):
        field = SECP256K1.field
        beta, _ = SECP256K1.endomorphism
        first = field - 1, 2 - field, 3
        second = 1 - field, field - 2, -5
        x, y = SECP256K1.generator
        for optimize in (False, True):
            library = ScriptBuilder("REQUIRE stdlib/secp256k1-window.fth", optimize=optimize)
            code = asm("17 OP_TOALTSTACK") + library.emit("secp-window-map-row-coordinates", b"")
            for sign in (-1, 1):
                qy = y * sign
                args = (field, x, *first, *second, qy, sign, beta)
                result, alt = evaluate(code, [b"caller", *map(encode_num, args)])
                expected = (x * beta % field, qy, 1,
                            first[0] * beta % field, first[1] * sign, first[2],
                            -(-second[0] * beta % field), second[1] * sign, second[2])
                self.assertEqual((result, alt), ([b"caller", *map(encode_num, expected)], [encode_num(17)]))

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

    def test_mapped_joint_with_shared_order_matches_embedded_order(self):
        library = ScriptBuilder("REQUIRE stdlib/secp256k1.fth")
        vocabulary = joint_vocabulary(library)
        options = dict(strategy=GLV_SCALED, scaled_output=True, mapped_input=True)
        direct, = link_joint_word(vocabulary, DATAFLOW, **options).values()
        shared, = link_joint_word(vocabulary, DATAFLOW, order_input=True, **options).values()
        x, y = SECP256K1.normalized_a0().affine(SECP256K1.generator)
        p, n = SECP256K1.field, SECP256K1.order
        save = asm("17 OP_TOALTSTACK")
        for s, k in ((0, 0), (0, n), (0, 1), (n - 1, 0), (1 << 255, n - 1), (7, n // 2)):
            with self.subTest(s=s, k=k):
                before = [b"caller", *map(encode_num, (x, y, s, k, p))]
                after = [b"caller", *map(encode_num, (x, y, p, s, k, n))]
                self.assertEqual(evaluate(save + shared.code, after), evaluate(save + direct.code, before))

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

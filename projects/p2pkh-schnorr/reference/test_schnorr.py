"""BIP340 interoperability and current-input authorization checks."""

import csv
from dataclasses import replace
from hashlib import sha256
from itertools import product
import os
from random import Random
import unittest

from coincurve import PrivateKey, PublicKeyXOnly
from coincurve._libsecp256k1 import ffi, lib
from coincurve.context import GLOBAL_CONTEXT

from bip340 import FIELD, ORDER, lift_x, to_bytes, verify
from payment import lock_for_public_key, sign_payment, sign_spend
from schnorr_script import (
    TEMPLATE_DIRS, TEMPLATE_VERSION, _contract, authorization_codes, compile_unlock, compiled_template,
    lock_for_owner, owner_hash, recognize, recognize_template, reconstruction_for_version, verifier,
)
from fourthgraph.benchmark.cases import native_coin
from fourthgraph.benchmark.validation import Node, chain_verdict
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, number, push
from fourthgraph.bsv.spend_authorization import SpendAuthorization, prepare_authorization
from fourthgraph.bsv.transaction import CHRONICLE, Input, Output, Transaction

VECTORS = TEMPLATE_DIRS["v0.6.0"] / "bip340-vectors.csv"
HALF_RADIX = 1 << 128
LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
MODES = (0x41, 0x42, 0x43, 0x61, 0x62, 0x63, 0xC1, 0xC2, 0xC3, 0xE1, 0xE2, 0xE3)


def official_vectors():
    raw = VECTORS.read_bytes()
    vectors = list(csv.DictReader(raw.decode("ascii").splitlines()))
    if (sha256(raw).hexdigest() != "01c8cabba63b4c9b2f44c975902990086a4fe56eee9d265b187d1e2c1d98ccfb"
            or [int(row["index"]) for row in vectors] != list(range(19))):
        raise ValueError("expected all 19 pinned official BIP340 vectors")
    return vectors


def affine_generator_multiple(scalar):
    public = PrivateKey.from_int(scalar % ORDER).public_key.format(compressed=False)
    return int.from_bytes(public[1:33], "big"), int.from_bytes(public[33:], "big")


def detached_unlock(message, public_key, signature, *, y=None, nonce_y=None):
    point = lift_x(public_key)
    nonce = lift_x(signature[:32])
    return b"".join(map(push, (
        message,
        public_key,
        to_bytes((point[1] if point else 0) if y is None else y),
        signature,
        to_bytes((nonce[1] if nonce else 0) if nonce_y is None else nonce_y),
    )))


def malformed_witnesses(public, message, signature):
    y = lift_x(public)[1]
    nonce_y = lift_x(signature[:32])[1]
    return (
        ("odd public ordinate", detached_unlock(message, public, signature, y=FIELD - y)),
        ("off-curve public ordinate", detached_unlock(message, public, signature, y=(y + 2) % FIELD)),
        ("noncanonical public ordinate", detached_unlock(message, public, signature, y=FIELD)),
        ("odd nonce ordinate", detached_unlock(message, public, signature, nonce_y=FIELD - nonce_y)),
        ("off-curve nonce ordinate", detached_unlock(message, public, signature, nonce_y=(nonce_y + 2) % FIELD)),
        ("noncanonical nonce ordinate", detached_unlock(message, public, signature, nonce_y=FIELD)),
        ("short signature", detached_unlock(message, public, signature[:-1])),
        ("extra stack item", push(b"extra") + detached_unlock(message, public, signature)),
    )


class SchnorrTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = (Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
                    if "REGTEST_COOKIE" in os.environ else None)
        # Public scalars and auxiliary randomness used exclusively by the fixtures.
        cls.keys = tuple(PrivateKey.from_int(scalar) for scalar in (3, 11))
        cls.public_keys = tuple(key.public_key_xonly.format() for key in cls.keys)
        cls.locks = tuple(lock_for_public_key(key) for key in cls.public_keys)
        cls.parents = tuple(
            Transaction((Input(bytes([20 + i]) * 32, 0),),
                        (Output(1, b"\x51"), Output(10_000, lock)))
            for i, lock in enumerate(cls.locks)
        )
        cls.unsigned = Transaction(
            tuple(Input(parent.txid_wire(), 1, sequence=0xfffffffe) for parent in cls.parents),
            tuple(Output(9_900, lock) for lock in reversed(cls.locks)),
        )

    def check_spend(self, tx, parents, expected):
        self.assertIs(chain_verdict(tx, parents), all(expected))
        if self.node:
            self.assertEqual(self.node.verdicts(tx, parents), expected)

    def check_detached(self, unlock, expected):
        lock = verifier()
        parent = Transaction((Input(b"\xfc" * 32, 0),), (Output(10_000, lock),))
        tx = Transaction((Input(parent.txid_wire(), 0, unlock),), (Output(9_900, b"\x51"),))
        self.check_spend(tx, (parent,), [expected])
        if expected:
            self.assertEqual(evaluate(unlock + lock), ([b"\x01"], []))
        else:
            with self.assertRaises(ScriptError):
                evaluate(unlock + lock)

    def test_bip340_official_vectors(self):
        for row in official_vectors():
            with self.subTest(index=row["index"], purpose=row["comment"]):
                public_key, message, signature = (
                    bytes.fromhex(row[field]) for field in ("public key", "message", "signature")
                )
                expected = row["verification result"] == "TRUE"
                try:
                    independent = PublicKeyXOnly(public_key).verify(signature, message)
                except ValueError:
                    independent = False
                self.assertIs(independent, expected)
                self.assertIs(verify(public_key, message, signature), expected)
                self.check_detached(detached_unlock(message, public_key, signature), expected)

    def test_bip340_official_signing_vectors(self):
        vectors = [row for row in official_vectors() if row["secret key"]]
        self.assertEqual([int(row["index"]) for row in vectors], [0, 1, 2, 3, 15, 16, 17, 18])
        for row in vectors:
            with self.subTest(index=row["index"]):
                secret, public, aux, message, expected = (bytes.fromhex(row[field]) for field in (
                    "secret key", "public key", "aux_rand", "message", "signature",
                ))
                self.assertEqual(PrivateKey(secret).public_key_xonly.format(), public)
                ctx = GLOBAL_CONTEXT.ctx
                keypair = ffi.new("secp256k1_keypair *")
                self.assertEqual(lib.secp256k1_keypair_create(ctx, keypair, secret), 1)
                # sign_custom accepts the empty and variable-length BIP340 vectors.
                entropy = ffi.new("unsigned char[32]", aux)
                params = ffi.new("secp256k1_schnorrsig_extraparams *", {
                    "magic": [0xda, 0x6f, 0xb3, 0x8c], "ndata": entropy,
                })
                signature = ffi.new("unsigned char[64]")
                self.assertEqual(lib.secp256k1_schnorrsig_sign_custom(
                    ctx, signature, message, len(message), keypair, params,
                ), 1)
                self.assertEqual(bytes(ffi.buffer(signature)), expected)

    def test_untrusted_coordinates_and_exact_encodings(self):
        public = self.public_keys[0]
        message = bytes(32)
        signature = self.keys[0].sign_schnorr(message, aux_randomness=bytes(32))
        for case, unlock in malformed_witnesses(public, message, signature):
            with self.subTest(case=case):
                self.check_detached(unlock, False)

    def sign_two_inputs(self, tx, sighash, parents=None, *, compress_otda=None):
        parents = self.parents if parents is None else parents
        for i, (parent, public, key) in enumerate(zip(parents, self.public_keys, self.keys, strict=True)):
            tx = sign_spend(tx, i, parent.serialize(), public,
                            lambda message: key.sign_schnorr(message, aux_randomness=bytes(32)),
                            sighash=sighash, chronicle_active=bool(sighash & CHRONICLE), compress_otda=compress_otda)
        return tx

    def test_sighash_type_encoding(self):
        check = _contract().emit("check-sighash", b"")
        for flag in range(256):
            packed = bytes([flag]) + bytes(3)
            if flag in MODES:
                self.assertEqual(evaluate(check, [packed]), ([bytes([flag])], []))
            else:
                with self.subTest(flag=flag), self.assertRaises(ScriptError):
                    evaluate(check, [packed])
        with self.assertRaises(ScriptError):
            evaluate(check, [b"\x41\x01\x00\x00"])

    def test_all_twelve_paired_payment_modes(self):
        for version in (1, 2):
            unsigned = replace(self.unsigned, version=version)
            for sighash in MODES:
                with self.subTest(version=version, sighash=hex(sighash)):
                    tx = self.sign_two_inputs(unsigned, sighash)
                    self.assertEqual(tx.with_script(0, b"").with_script(1, b""), unsigned)
                    self.check_spend(tx, self.parents, [True, True])
                    self.check_spend(replace(tx, locktime=1), self.parents, [False, False])
                    output = replace(tx.outputs[0], value=9_899)
                    changed = replace(tx, outputs=(output, tx.outputs[1]))
                    expected = {1: [False, False], 2: [True, True], 3: [False, True]}[sighash & 31]
                    self.check_spend(changed, self.parents, expected)

    def test_payment_to_native_p2pkh_outputs(self):
        recipients = tuple(native_coin(f"schnorr/recipient/{index}", 6_600).output for index in range(3))
        for version, sighash in ((1, 0x41), (2, 0x61)):
            with self.subTest(version=version, sighash=hex(sighash)):
                unsigned = replace(self.unsigned, version=version, outputs=recipients)
                signed = self.sign_two_inputs(unsigned, sighash)
                self.assertEqual(signed.outputs, recipients)
                ordinary, companion = authorization_codes()
                for index, txin in enumerate(signed.inputs):
                    auth = prepare_authorization(unsigned, index, 10_000, sighash,
                                                 ordinary_code=ordinary, companion_code=companion)
                    fields, alt = evaluate(txin.script)
                    self.assertEqual(txin.script, auth.witness(fields[1]))
                    self.assertFalse(alt)
                self.check_spend(signed, self.parents, [True, True])
                changed = replace(signed, outputs=(*recipients[:-1], replace(recipients[-1], value=6_599)))
                self.check_spend(changed, self.parents, [False, False])

    def test_otda_constructor_matches_every_frozen_output_template(self):
        for version in TEMPLATE_DIRS:
            with self.subTest(version=version):
                pattern = reconstruction_for_version(version)
                fixed, alt = evaluate(pattern.program, [b"outer"])
                self.assertEqual((fixed, alt), ([b"outer", *pattern.fixed_parts], []))
                for owner in (bytes(20), bytes(range(20)), bytes([255]) * 20):
                    lock = lock_for_owner(owner, version=version)
                    self.assertEqual(pattern.match(lock), (owner,))
                    self.assertEqual(fixed[1] + owner + fixed[2], lock)
                    self.assertIsNone(pattern.match(lock[:-1] + b"\x51"))

    def test_otda_constructor_preserves_literal_witness_and_mixed_outputs(self):
        older = Output(8_500, lock_for_public_key(self.public_keys[0], version="v0.16.0"))
        native = native_coin("schnorr/constructor/native", 1_000).output
        outputs = self.unsigned.outputs[0], native, older
        for version, flag, expected in (
            (1, 0x61, (False, False)), (2, 0x41, (False, False)),
            (2, 0x61, (True, True)), (2, 0xe1, (True, True)), (2, 0x62, (False, False)),
            (2, 0x63, (True, False)), (2, 0xe3, (True, False)),
        ):
            with self.subTest(version=version, flag=hex(flag)):
                tx = replace(self.unsigned, version=version, outputs=outputs)
                literal = self.sign_two_inputs(tx, flag, compress_otda=False)
                signed = self.sign_two_inputs(tx, flag)
                for i, (encoded, original) in enumerate(zip(signed.inputs, literal.inputs, strict=True)):
                    self.assertEqual(evaluate(encoded.script), evaluate(original.script))
                    if expected[i]:
                        self.assertLess(len(encoded.script), len(original.script))
                    else:
                        self.assertEqual(encoded.script, original.script)
                self.check_spend(signed, self.parents, [True, True])
                if any(expected):
                    self.check_spend(literal, self.parents, [True, True])
                if flag & 31 == 1:
                    self.check_spend(replace(signed, outputs=tuple(reversed(outputs))), self.parents, [False, False])
        activation = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", "2"))
        context = dict(spend_height=activation + 1, activation_height=activation,
                       utxo_heights=(activation - 1,) * 2)
        rebuilt = self.sign_two_inputs(replace(self.unsigned, outputs=outputs), 0x61)
        validate_at_heights(rebuilt, self.parents, **context)
        if self.node:
            self.assertEqual(self.node.verdicts(rebuilt, self.parents, **context), [True, True])

    def test_bip143_spend_before_chronicle(self):
        signed = self.sign_two_inputs(self.unsigned, 0x41)
        activation_height = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", "2"))
        # Genesis starts at height 1. The default Chronicle height leaves one eligible block.
        height = activation_height - 1
        context = dict(spend_height=height, activation_height=activation_height, utxo_heights=(height, height))
        validate_at_heights(signed, self.parents, **context)
        if self.node:
            self.assertEqual(self.node.verdicts(signed, self.parents, **context), [True, True])

    def test_payment_and_preflight(self):
        parent = self.parents[0].serialize()
        public = self.public_keys[0]
        target = Output(9_900, self.locks[1])
        self.assertEqual(recognize(self.locks[0]), owner_hash(public))
        self.assertEqual(lock_for_owner(owner_hash(public)), self.locks[0])
        self.assertIsNone(recognize(self.locks[0][:-1] + b"\x51"))
        signed = sign_payment(parent, 1, (target,), 100, public,
                              lambda message: self.keys[0].sign_schnorr(message, aux_randomness=bytes(32)))
        self.check_spend(signed, self.parents[:1], [True])
        for invalid in (None, bytes(63), bytes(64), bytearray(64)):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "invalid BIP340 signature"):
                sign_payment(parent, 1, (target,), 100, public, lambda _: invalid)

        def unexpected(_):
            self.fail("invalid payment reached the signer")

        with self.assertRaisesRegex(ValueError, "balance"):
            sign_payment(parent, 1, (target,), 99, public, unexpected)
        with self.assertRaisesRegex(ValueError, "active spend context"):
            sign_spend(self.unsigned, 0, parent, public, unexpected, sighash=0x61)
        with self.assertRaisesRegex(ValueError, "active spend context"):
            sign_spend(self.unsigned, 0, parent, public, unexpected, compress_otda=True)
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            sign_spend(self.unsigned, 0, parent, public, unexpected, compress_otda=1)
        with self.assertRaisesRegex(ValueError, "same-index"):
            sign_spend(replace(self.unsigned, outputs=(target,)), 1, self.parents[1].serialize(),
                       self.public_keys[1], unexpected, sighash=0x43)
        with self.assertRaisesRegex(ValueError, "funding outpoint"):
            sign_spend(self.unsigned, 1, parent, public, unexpected)
        with self.assertRaisesRegex(ValueError, "key and template"):
            sign_spend(self.unsigned, 0, parent, self.public_keys[1], unexpected)

    def test_frozen_template(self):
        reference, offset = compiled_template()
        self.assertEqual(lock_for_owner(bytes(20)), reference)
        owner = bytes(range(20))
        raw = lock_for_owner(owner)
        self.assertEqual(raw, reference[:offset] + owner + reference[offset + 20:])
        self.assertEqual(compiled_template(owner), (raw, offset))
        self.assertEqual(recognize_template(raw), (TEMPLATE_VERSION, owner))
        self.assertLess(len(raw), len(lock_for_owner(bytes(20), version="v0.16.0")))

    def test_mixed_template_spend(self):
        public = self.public_keys[0]
        first, second = self.parents
        first_input, second_input = self.unsigned.inputs
        versions = {
            "v0.6.0": "12c75b80b65e983369998e8c2ba581979bb1d4cc67c99a4f8694394447a6a877",
            "v0.7.0": "b1aff80ac6a66e83cf915f6636b54fd7853b2803543d2410a19840efb50ad966",
            "v0.8.0": "eafc3937ba802a3fcfeae3bf7a814a747be3c797906c86e330cd68001f3509e5",
            "v0.9.0": "8c58eb80a5adb4aaf1256db2f12e0f4bbc551885e919200350621481a45de0a3",
            "v0.10.0": "48411a610a80dbeba846332ef28f78c7ee3dedeaa131e82faa89f6cd24b88f83",
            "v0.11.0": "88b7b3a46548ca376a29fe04bb0deb11f2a503d9cf5de92e89604aa490660fdc",
            "v0.12.0": "0c867581a116fd86be8aaa6f3c700742d265df4473e77ba9f2344c13122841e2",
            "v0.13.0": "0c09881b86ddfa644701e4f2bd6bdeee5930095fcdfdaf07e2ce38be2f960f27",
            "v0.14.0": "c70c3b816478caa5fa6086a770484e629d1df75c1477d8436875ea78c1f09f76",
            "v0.15.0": "abf968180a0f6a84422bfe02d9e4b5533b2cdf7a1df9a59bf5afae6343965c26",
            "v0.16.0": "1b4d0170a8a4677242400ca046319b8d20c26881391503475178e013d6cba2c3",
        }
        for version, checksum in versions.items():
            raw = lock_for_public_key(public, version=version)
            self.assertEqual(sha256(lock_for_owner(bytes(20), version=version)).hexdigest(), checksum)
            self.assertEqual(recognize_template(raw), (version, owner_hash(public)))
            self.assertIsNone(recognize_template(raw[:-1] + b"\x51"))
            legacy = replace(first.outputs[1], script=raw)
            parents = (replace(first, outputs=(first.outputs[0], legacy)), second)
            inputs = (replace(first_input, txid=parents[0].txid_wire()), second_input)
            unsigned = replace(self.unsigned, inputs=inputs)
            for sighash in MODES:
                with self.subTest(version=version, sighash=hex(sighash)):
                    signed = self.sign_two_inputs(unsigned, sighash, parents)
                    self.check_spend(signed, parents, [True, True])
                    self.check_spend(replace(signed, locktime=1), parents, [False, False])

    def test_forth_unlock_preserves_witness_encoding(self):
        witness = (b"x" * 32, b"y" * 32, b"s" * 64, b"r" * 32)
        for size in (75, 76, 255, 256, 65535, 65536):
            for companion in (False, True):
                with self.subTest(preimage_bytes=size, companion=companion):
                    preimage = bytes(size)
                    auth = SpendAuthorization(0x63 if companion else 0x41, preimage, companion)
                    self.assertEqual(compile_unlock(preimage, companion, *witness),
                                     auth.witness(b"".join(witness)))

    def test_fixed_width_byte_reversal(self):
        contract = _contract()
        reverse = contract.emit("script-reverse32", b"")
        setup = push(b"saved") + asm("OP_TOALTSTACK")
        for value in (bytes(range(32)), bytes(32), b"\xff" + bytes(31)):
            self.assertEqual(evaluate(setup + reverse, [b"prefix", value]),
                             ([b"prefix", value[::-1]], [b"saved"]))

        reverse_fields = contract.emit("bip340-reverse-challenge-fields", b"")
        data = bytes(range(192))
        expected = b"".join(data[start:start + 32][::-1] for start in range(0, 192, 32))
        self.assertEqual(evaluate(setup + reverse_fields, [b"prefix", data]),
                         ([b"prefix", expected], [b"saved"]))

    def test_forth_lock_accepts_unpaired_otda_companion(self):
        unsigned = replace(self.unsigned, outputs=self.unsigned.outputs[:1])
        tx = sign_spend(unsigned, 0, self.parents[0].serialize(), self.public_keys[0],
                        lambda message: self.keys[0].sign_schnorr(message, aux_randomness=bytes(32)))
        ordinary_code, companion_code = authorization_codes()
        public = self.public_keys[1]
        for sighash in (0x63, 0xE3):
            with self.subTest(sighash=hex(sighash)):
                auth = prepare_authorization(tx, 1, self.parents[1].outputs[1].value, sighash,
                                             ordinary_code=ordinary_code, companion_code=companion_code)
                self.assertTrue(auth.companion)
                signature = self.keys[1].sign_schnorr(auth.checked_digest(), aux_randomness=bytes(32))
                witness = (public, to_bytes(lift_x(public)[1]), signature, to_bytes(lift_x(signature[:32])[1]))
                unlock = compile_unlock(auth.preimage, True, *witness)
                self.check_spend(tx.with_script(1, unlock), self.parents, [True, True])
                wrong_mode = compile_unlock(auth.preimage, False, *witness)
                self.check_spend(tx.with_script(1, wrong_mode), self.parents, [True, False])

    def test_doubling_agrees_with_complete_addition(self):
        contract = _contract()
        double = contract.emit("secp256k1-double", b"")
        pair = contract.emit("secp256k1-double-pair", b"")
        pair_adjacent = contract.emit("secp256k1-double-pair-with-field", b"", 1)
        add = contract.emit("secp256k1-add", b"")
        points = [(0, 1, 0)]
        for scalar in range(1, 17):
            x, y = affine_generator_multiple(scalar)
            for z in (1, -17, FIELD - 1):
                points.append((x * z % FIELD, y * z % FIELD, z))

        for point in points:
            with self.subTest(point=point):
                encoded = b"".join(map(number, point))
                old, old_alt = evaluate(number(FIELD) + encoded * 2 + add)
                new, new_alt = evaluate(number(FIELD) + encoded + double)
                self.assertEqual((old_alt, new_alt), ([], []))
                self.assertEqual(len(new), 4)
                self.assertEqual(decode_num(new[0]), FIELD)
                self.assertEqual([decode_num(item) % FIELD for item in old[1:]],
                                 [decode_num(item) % FIELD for item in new[1:]])
                separate, separate_alt = evaluate(double, new)
                combined, combined_alt = evaluate(pair, [encode_num(FIELD), *map(encode_num, point)])
                self.assertEqual((separate_alt, combined_alt), ([], []))
                self.assertEqual([decode_num(item) % FIELD for item in separate],
                                 [decode_num(item) % FIELD for item in combined])
                adjacent = [b"outer", encode_num(FIELD), *map(encode_num, point)]
                self.assertEqual(evaluate(pair_adjacent, adjacent), ([b"outer", *combined], []))

    def test_lambda_scalar_split(self):
        split = _contract().emit("secp256k1-lambda-split", b"")
        rng = Random(340)
        scalars = (0, 1, HALF_RADIX - 1, HALF_RADIX, ORDER // 2, ORDER - 2, ORDER - 1, ORDER)
        signs = set()
        for k in (*scalars, *(rng.randrange(ORDER) for _ in range(64))):
            with self.subTest(k=k):
                stack, alt = evaluate(split, [b"outer", encode_num(k)])
                self.assertEqual(alt, [])
                self.assertEqual(stack[:1], [b"outer"])
                k1, k2 = map(decode_num, stack[1:])
                self.assertLess(abs(k1), HALF_RADIX)
                self.assertLess(abs(k2), HALF_RADIX)
                self.assertEqual((k1 + LAMBDA * k2) % ORDER, k % ORDER)
                if k1 and k2:
                    signs.add((k1 < 0, k2 < 0))
        self.assertEqual(len(signs), 4)

    def test_affine_add_matches_complete_addition(self):
        contract = _contract()
        full = contract.emit("secp256k1-add", b"")
        mixed = contract.emit("secp256k1-add-affine", b"")
        full_adjacent = contract.emit("secp256k1-add-with-field", b"", 1)
        mixed_adjacent = contract.emit("secp256k1-add-affine-with-field", b"", 1)
        for a in (0, 1, -1, 7):
            for b in (1, -1, 7):
                with self.subTest(a=a, b=b):
                    bx, by = affine_generator_multiple(b)
                    if a:
                        ax, ay = affine_generator_multiple(a)
                        z = -17
                        left = (ax * z % FIELD, ay * z % FIELD, z)
                    else:
                        left = (0, 1, 0)
                    stack = [encode_num(FIELD), b"outer", *map(encode_num, (*left, bx, by))]
                    expected, alt = evaluate(mixed, stack)
                    self.assertEqual((expected, alt), evaluate(full, [*stack, encode_num(1)]))
                    adjacent = [stack[1], stack[0], *stack[2:]]
                    expected_adjacent = ([expected[1], expected[0], *expected[2:]], alt)
                    self.assertEqual(evaluate(mixed_adjacent, adjacent), expected_adjacent)
                    self.assertEqual(evaluate(full_adjacent, [*adjacent, encode_num(1)]), expected_adjacent)

    @staticmethod
    def window_stream(scalars):
        return bytes(sum(((value >> shift) & 3) << (2 * lane) for lane, value in enumerate(scalars))
                     for shift in range(126, -1, -2))

    def test_window_stream_packing(self):
        pack = _contract().emit("bip340-pack-windows", b"")
        pack_fixed_scalar = _contract().emit("secp-window-pack-fixed-scalar", b"")

        def check_packing(lanes, expected):
            low, high, first, second = lanes
            fixed = (low | (high << 128), first, second)
            for script, values in ((pack, lanes), (pack_fixed_scalar, fixed)):
                self.assertEqual(evaluate(script, [b"outer", *map(encode_num, values)]),
                                 ([b"outer", expected], []))

        for lane in range(4):
            for digit in range(64):
                with self.subTest(lane=lane, digit=digit):
                    values = [0] * 4
                    values[lane] = 3 << (2 * digit)
                    expected = bytearray(64)
                    expected[63 - digit] = 3 << (2 * lane)
                    check_packing(values, bytes(expected))
        rng = Random(340)
        vectors = ([0] * 4, [HALF_RADIX - 1] * 4,
                   *(tuple(rng.getrandbits(128) for _ in range(4)) for _ in range(64)))
        for scalars in vectors:
            check_packing(scalars, self.window_stream(scalars))

    def test_joint_window_table_and_selectors(self):
        contract = _contract()
        split = contract.emit("secp256k1-lambda-split", b"")
        order = number(ORDER) + asm("OP_TOALTSTACK")
        table = contract.emit("bip340-joint-window-table", order)
        first = contract.emit("bip340-first-window", b"")
        step = contract.emit("bip340-joint-window-step", b"")
        depths = contract.emit("bip340-window-depths", b"")
        (scale_bytes,), alt = evaluate(contract.emit("secp256k1-scale-root", b""))
        self.assertEqual(alt, [])
        scale = decode_num(scale_bytes)
        self.assertEqual(21 * pow(scale, 6, FIELD) % FIELD, 1)
        scale_x, scale_y = pow(scale, 2, FIELD), pow(scale, 3, FIELD)
        unscale_x, unscale_y = pow(scale_x, -1, FIELD), pow(scale_y, -1, FIELD)

        def check_point(coordinates, scalar):
            x, y, z = (decode_num(item) % FIELD for item in coordinates)
            if scalar % ORDER == 0:
                self.assertEqual((x, z), (0, 0))
                self.assertNotEqual(y, 0)
            else:
                inverse = pow(z, -1, FIELD)
                affine = (x * inverse * unscale_x % FIELD, y * inverse * unscale_y % FIELD)
                self.assertEqual(affine, affine_generator_multiple(scalar))

        def fixed_depth(index):
            return 3 + 2 * index if index else 0

        def variable_depth(index):
            return 82 - 3 * index if index else 0

        def depth_pairs(windows):
            return bytes(depth for digit in windows
                         for depth in (variable_depth(digit >> 4), fixed_depth(digit & 15)))

        depth_vectors = [bytes(64), b"\xff" * 64]
        depth_vectors.extend(bytes(range(start, start + 64)) for start in range(0, 256, 64))
        for windows in depth_vectors:
            self.assertEqual(evaluate(depths, [windows]), ([depth_pairs(windows)], []))

        cases = (
            (1, ORDER - 1, 13), (-1, HALF_RADIX, ORDER),
            (2, 0, ORDER // 2), (5, HALF_RADIX + 17, ORDER // 4),
            (-7, HALF_RADIX - 1, ORDER // 7), (11, ORDER - 2, ORDER // 8),
        )
        signs = set()
        for public_multiple, s, k in cases:
            px, py = affine_generator_multiple(public_multiple)
            original = [FIELD, 123, 456, px, py, s, k]
            scalars, _ = evaluate(split, [encode_num(k)])
            k1, k2 = map(decode_num, scalars)
            if k1 and k2:
                signs.add((k1 < 0, k2 < 0))
            p = -public_multiple if k1 < 0 else public_multiple
            q = LAMBDA * (-public_multiple if k2 < 0 else public_multiple)
            built, alt = evaluate(table, list(map(encode_num, original)))
            scalar_lanes = (s % HALF_RADIX, s // HALF_RADIX, abs(k1), abs(k2))
            windows = self.window_stream(scalar_lanes)
            self.assertEqual(alt, [depth_pairs(windows)])
            self.assertEqual(len(built), 81)
            self.assertEqual(list(map(decode_num, built[:2])), [123 * scale_x % FIELD, 456 * scale_y % FIELD])
            self.assertEqual(list(map(decode_num, built[-4:])), [FIELD, 0, 1, 0])
            for index in range(1, 16):
                with self.subTest(public_multiple=public_multiple, table_index=index):
                    high, low = divmod(index, 4)
                    start = 2 + 3 * (index - 1)
                    check_point(built[start:start + 3], high * q + low * p)
                    start = 47 + 2 * (15 - index)
                    x, y = map(decode_num, built[start:start + 2])
                    self.assertEqual((x * unscale_x % FIELD, y * unscale_y % FIELD),
                                     affine_generator_multiple(high * HALF_RADIX + low))

            for fixed, variable in product(range(16), repeat=2):
                with self.subTest(public_multiple=public_multiple, fixed=fixed, variable=variable):
                    high, low = divmod(fixed, 4)
                    vhigh, vlow = divmod(variable, 4)
                    remaining = b"\x25\x21"
                    stream = bytes([variable_depth(variable), fixed_depth(fixed)]) + remaining
                    setup = push(stream) + asm("OP_TOALTSTACK")
                    scalar = high * HALF_RADIX + low + vhigh * q + vlow * p
                    for window in (first, step):
                        selected, alt = evaluate(setup + window, built)
                        self.assertEqual(alt, [remaining])
                        self.assertEqual(selected[:-3], built[:-3])
                        check_point(selected[-3:], scalar)
        self.assertEqual(signs, set(product((False, True), repeat=2)))

    def test_joint_multiplication_scalar_edges(self):
        order = number(ORDER) + asm("OP_TOALTSTACK")
        multiply = _contract().emit("bip340-joint-multiply", order)
        px, py = affine_generator_multiple(1)
        cases = ((0, ORDER), (0, ORDER - 1), (1, ORDER), (1, ORDER - 1),
                 (HALF_RADIX - 1, 1), (HALF_RADIX, ORDER - HALF_RADIX),
                 (ORDER - 1, ORDER - 1))
        for s, k in cases:
            with self.subTest(s=s, k=k):
                multiple = (s + k) % ORDER
                r, ry = affine_generator_multiple(multiple) if multiple else (0, 0)
                stack = list(map(encode_num, (FIELD, r, ry, px, py, s, k)))
                if multiple:
                    self.assertEqual(evaluate(multiply, stack), ([b"\x01"], []))
                else:
                    with self.assertRaises(ScriptError):
                        evaluate(multiply, stack)


if __name__ == "__main__":
    unittest.main()

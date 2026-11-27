"""WOTS+ reference tests and development Script checks."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import unittest

from fixtures import fixture_seeds, funding_transaction, mode_fixture, vector_document
from payment import sign_payment
from script import (
    BUFFERED_PROFILES, CACHE_PROFILES, COMPACT_PROFILES, COMPANION_CODE, FIRST_ADDRESS_NORMALIZED_PROFILES,
    LAZY_MESSAGE_PROFILES, ORDINARY_CODE, _buffered_message_digits, _message_digits, _packed_step_suffixes,
    locking_script,
)
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.pushtx import N as CURVE_ORDER, R as BINDING_R, authorization_checks, binding_der, check_binding
from fourthgraph.bsv.script import asm, decode_num, number, push
from fourthgraph.bsv.transaction import SIGHASH_TYPES, Output
from wots import (
    CHAINS,
    KEY_BYTES,
    N,
    SIGNATURE_BYTES,
    OneTimeSigner,
    digits,
    generate_keypair,
    public_key,
    sign_digest,
    verify_digest,
)


class WotsTests(unittest.TestCase):
    def test_pinned_xmss_reference_c_vectors(self):
        # XMSS/xmss-reference at 171ccbd26f098542a67eb5d2b128281c80bd71a6.
        # wots_pkgen and wots_sign use WOTSP-SHA2_256 and an all-zero OTS
        # address. wots_pk_from_sig recovered the same 67 packed endpoints
        # from each signature. These are the OpenSSL SHA-256 fingerprints.
        secret = bytes(range(32))
        public_seed = bytes(range(32, 64))
        key = public_key(secret, public_seed)
        self.assertEqual(key[:32], public_seed)
        self.assertEqual(key[32:].hex(), "f3888f471037ef42994f1bcbef0d98f6373ea20cb61cf3d1b4360e68179b4fed")

        locks = [locking_script(key, transaction=False, cached_constants=cache)
                 for cache in CACHE_PROFILES]
        self.assertEqual(len(locking_script(key)), 42266)
        self.assertEqual(len(locking_script(key, cached_constants=True)), 36283)
        for digest, signature_hash in (
            (bytes(32), "1e100d3eb4888cf851362ed60345bf26439eee93b5ed7368d63afcaf818330d8"),
            (b"\xff" * 32, "07a68e120bae2a47019c4b64928e205e37bcac32e3173378a7858cf833fa54ee"),
            (bytes(range(32)), "9b85f87db0028a89487a147e2f33a114d81e96c82d0be1b0dd82dfce11f3217a"),
            (bytes(0x80 + 3 * i for i in range(32)), "da25cf118c25ab18776831c25e9be3a206079b5d030a8bcd0e4c80d1765d78a0"),
        ):
            with self.subTest(digest=digest.hex()):
                sig = sign_digest(secret, public_seed, digest)
                self.assertEqual(sha256(sig).hexdigest(), signature_hash)
                self.assertTrue(verify_digest(key, digest, sig))
                for lock in locks:
                    self.assertEqual(evaluate(lock, [digest, sig]), ([b"\x01"], []))

    def test_nibble_order_and_checksum(self):
        self.assertEqual(digits(bytes(32)), (0,) * 64 + (3, 12, 0))
        self.assertEqual(digits(b"\xff" * 32), (15,) * 64 + (0, 0, 0))
        self.assertEqual(digits(b"\xab" + bytes(31)), (10, 11) + (0,) * 62 + (3, 10, 11))

    def test_compact_countdown_for_each_digit(self):
        for digit in range(16):
            with self.subTest(digit=digit):
                seeds = fixture_seeds(b"countdown/" + bytes([digit]))
                key = public_key(*seeds)
                digest = bytes([17 * digit]) * N
                signature = sign_digest(*seeds, digest)
                for profile in COMPACT_PROFILES[1:]:
                    lock = locking_script(key, transaction=False, cached_constants=profile)
                    self.assertEqual(evaluate(lock, [digest, signature]), ([b"\x01"], []), profile)

    def test_bitwise_digest_decoder_matches_for_every_byte(self):
        reference = _message_digits(step_counts=True)
        for profile in FIRST_ADDRESS_NORMALIZED_PROFILES:
            bitwise = _buffered_message_digits(profile)
            for value in range(256):
                with self.subTest(profile=profile, value=value):
                    for digest in (bytes([value]) * N, bytes(value ^ index for index in range(N))):
                        stack = [b"fixture signature", digest]
                        expected_main, expected_counts = evaluate(reference, stack)
                        main, alt = evaluate(bitwise, stack)
                        self.assertEqual(main, expected_main)
                        if profile in LAZY_MESSAGE_PROFILES:
                            self.assertEqual(alt, [bytes(byte ^ 255 for byte in digest)])
                        else:
                            self.assertEqual(list(map(decode_num, alt)), list(map(decode_num, expected_counts)))

    def test_packed_step_suffixes_match_the_prf_address_layout(self):
        delta = bytes(87) + b"\x01"
        expected = [step.to_bytes(4, "big") + bytes(4) for step in reversed(range(15))]
        expected.insert(3, delta)
        self.assertEqual(evaluate(_packed_step_suffixes(push(delta))), (expected, []))

    def test_compact_authorization_for_every_flag_byte(self):
        _, _, spend = mode_fixture(0x41)
        (preimage, signature, selector), _ = evaluate(spend.inputs[1].script)
        code = authorization_checks(ORDINARY_CODE, COMPANION_CODE, compact=True)
        for flag in range(256):
            with self.subTest(flag=flag):
                flag_byte = bytes([flag])
                candidate = preimage[:-4] + flag_byte + bytes(3)
                if flag in SIGHASH_TYPES:
                    self.assertEqual(evaluate(code, [candidate, signature, selector]),
                                     ([candidate, signature], [selector, flag_byte]))
                else:
                    with self.assertRaises(ScriptError):
                        evaluate(code, [candidate, signature, selector])

    def test_compact_companion_shape_checks_flags_and_zero_output_hash(self):
        _, _, spend = mode_fixture(0x63, paired=False)
        (preimage, signature, selector), _ = evaluate(spend.inputs[1].script)
        code = authorization_checks(ORDINARY_CODE, COMPANION_CODE, compact=True, compact_shape=True)
        for flag in range(256):
            with self.subTest(flag=flag):
                flag_byte = bytes([flag])
                candidate = preimage[:-4] + flag_byte + bytes(3)
                if flag in (0x43, 0xc3):
                    self.assertEqual(evaluate(code, [candidate, signature, selector]),
                                     ([candidate, signature], [selector, flag_byte]))
                else:
                    with self.assertRaises(ScriptError):
                        evaluate(code, [candidate, signature, selector])
        start = 117 + len(COMPANION_CODE)
        for offset in range(start, start + N):
            with self.subTest(offset=offset):
                mutated = preimage[:offset] + b"\x80" + preimage[offset + 1:]
                with self.assertRaises(ScriptError):
                    evaluate(code, [mutated, signature, selector])

    def test_compact_der_matches_at_modular_boundaries(self):
        for scalar in (0, CURVE_ORDER // 2 - BINDING_R, CURVE_ORDER // 2 - BINDING_R + 1,
                       CURVE_ORDER - BINDING_R - 1, CURVE_ORDER - BINDING_R + 1, 2**256 - 1):
            digest = scalar.to_bytes(32, "big")
            self.assertEqual(evaluate(binding_der(compact=True), [digest]), evaluate(binding_der(), [digest]))
        zero = (CURVE_ORDER - BINDING_R).to_bytes(32, "big")
        with self.assertRaises(ScriptError):
            evaluate(binding_der(compact=True), [zero])

    def test_compact_address_increment_with_boundary_seeds(self):
        secret, _ = fixture_seeds(b"buffered-address")
        for seed in (bytes(N), b"\xff" * N, b"\x00\x80" * (N // 2)):
            with self.subTest(seed=seed):
                key = public_key(secret, seed)
                locks = [locking_script(key, transaction=False, cached_constants=profile)
                         for profile in BUFFERED_PROFILES]
                for digest in (bytes(N), b"\xff" * N, bytes(range(N))):
                    signature = sign_digest(secret, seed, digest)
                    for lock in locks:
                        self.assertEqual(evaluate(lock, [digest, signature]), ([b"\x01"], []))

    def test_binding_key_and_der_reuse_pass_the_same_checksigs(self):
        digest = sha256(b"binding key reuse fixture").digest()
        for mode, flag in ((0, 0x41), (1, 0x43), (1, 0xc3)):
            prefix = number(mode) + asm("OP_TOALTSTACK") + push(bytes([flag])) + asm("OP_TOALTSTACK")
            expected = []
            actual = []
            compressed = []

            def capture(calls):
                def checksig(signature, key):
                    calls.append((signature, key))
                    return True
                return checksig

            with self.subTest(mode=mode, flag=flag):
                for reuse, derive_der, calls in ((False, False, expected), (True, False, actual),
                                                 (True, True, compressed)):
                    code = prefix + check_binding(
                        COMPANION_CODE, compact=True, reuse_r=reuse, compact_companion=derive_der,
                    )
                    self.assertEqual(evaluate(code, [digest], capture(calls)), ([b"\x01"], []))
                self.assertEqual(len(actual), 1 + mode)
                self.assertEqual(actual, expected)
                self.assertEqual(compressed, expected)

    def test_keys_and_malformed_values(self):
        secret, key = generate_keypair()
        self.assertEqual((len(secret), len(key)), (N, KEY_BYTES))
        self.assertEqual(public_key(secret, key[:N]), key)
        self.assertNotEqual(generate_keypair()[1], key)
        digest = bytes(N)
        signature = sign_digest(secret, key[:N], digest)
        self.assertEqual(len(signature), SIGNATURE_BYTES)
        for bad in (b"", bytes(N - 1), bytes(N + 1), None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sign_digest(secret, key[:N], bad)
                with self.assertRaises(ValueError):
                    public_key(bad, key[:N])
                self.assertFalse(verify_digest(key, bad, signature))
        for bad_key in (key[:-1], key + b"\x00", None):
            self.assertFalse(verify_digest(bad_key, digest, signature))
        for bad_signature in (signature[:-1], signature + b"\x00", None):
            self.assertFalse(verify_digest(key, digest, bad_signature))
        lock = locking_script(key, transaction=False)
        for witness in ([digest[:-1], signature], [digest + b"\x00", signature],
                        [digest, signature[:-1]], [digest, signature + b"\x00"]):
            with self.assertRaises(ScriptError):
                evaluate(lock, witness)

    def test_every_signature_chain_is_checked(self):
        seeds = fixture_seeds(b"chain-mutation")
        key = public_key(*seeds)
        digest = sha256(b"signed digest").digest()
        signature = sign_digest(*seeds, digest)
        lock = locking_script(key, transaction=False)
        self.assertFalse(verify_digest(key, sha256(b"other digest").digest(), signature))
        self.assertFalse(verify_digest(public_key(*fixture_seeds(b"other-key")), digest, signature))
        for chain in range(CHAINS):
            with self.subTest(chain=chain):
                mutated = bytearray(signature)
                mutated[chain * N] ^= 1
                self.assertFalse(verify_digest(key, digest, bytes(mutated)))
                with self.assertRaises(ScriptError):
                    evaluate(lock, [digest, bytes(mutated)])

    def test_one_time_signer_is_atomic(self):
        signer = OneTimeSigner(*fixture_seeds(b"parallel-use"))
        with self.assertRaises(ValueError):
            signer(b"invalid digest")
        digest = bytes(N)

        def attempt(_):
            try:
                return signer(digest)
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            signatures = [sig for sig in pool.map(attempt, range(16)) if sig is not None]
        self.assertEqual(len(signatures), 1)
        self.assertTrue(verify_digest(signer.public_key, digest, signatures[0]))
        with self.assertRaises(ValueError):
            signer(digest)

    def test_payment_preflight_and_external_signer_callback(self):
        key = public_key(*fixture_seeds())
        parent = funding_transaction(key)
        calls = []

        def wrong_signature(digest):
            calls.append(digest)
            return bytes(SIGNATURE_BYTES)

        same_key_outputs = [(0, [Output(9_900, locking_script(key, transaction=transaction,
                                                              cached_constants=profile))])
                            for profile in CACHE_PROFILES for transaction in (True, False)]
        for vout, outputs in (
            (1, [Output(9_900, b"\x51")]),
            (0, [Output(9_899, b"\x51")]),
            *same_key_outputs,
        ):
            with self.subTest(vout=vout, output_bytes=len(outputs[0].script)):
                with self.assertRaises(ValueError):
                    sign_payment(parent.serialize(), vout, outputs, 100, key, wrong_signature)
        committed_steps = funding_transaction(key, cached_constants="steps")
        with self.assertRaisesRegex(ValueError, "fresh WOTS\\+ key"):
            sign_payment(committed_steps.serialize(), 0, [Output(9_900, locking_script(key))],
                         100, key, wrong_signature)
        self.assertEqual(calls, [])
        with self.assertRaises(ValueError):
            sign_payment(parent.serialize(), 0, [Output(9_900, b"\x51")], 100, key, wrong_signature)
        self.assertEqual(len(calls), 1)

    def test_payment_vectors_are_reproducible(self):
        path = Path(__file__).resolve().parents[1] / "versions/v0.1.0" / "vectors.json"
        self.assertEqual(json.loads(path.read_text()), vector_document())


if __name__ == "__main__":
    unittest.main()

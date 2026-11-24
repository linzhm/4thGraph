"""WOTS+ reference tests and development Script checks."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import unittest

from fixtures import fixture_seeds, funding_transaction, vector_document
from payment import sign_payment
from script import locking_script
from shared.evaluate import ScriptError, evaluate
from shared.transaction import Output
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

        lock = locking_script(key, transaction=False)
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
                self.assertEqual(evaluate(lock, [digest, sig]), ([b"\x01"], []))

    def test_nibble_order_and_checksum(self):
        self.assertEqual(digits(bytes(32)), (0,) * 64 + (3, 12, 0))
        self.assertEqual(digits(b"\xff" * 32), (15,) * 64 + (0, 0, 0))
        self.assertEqual(digits(b"\xab" + bytes(31)), (10, 11) + (0,) * 62 + (3, 10, 11))

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

        for vout, outputs in (
            (1, [Output(9_900, b"\x51")]),
            (0, [Output(9_899, b"\x51")]),
            (0, [Output(9_900, locking_script(key))]),
            (0, [Output(9_900, locking_script(key, transaction=False))]),
        ):
            with self.assertRaises(ValueError):
                sign_payment(parent.serialize(), vout, outputs, 100, key, wrong_signature)
        self.assertEqual(calls, [])
        with self.assertRaises(ValueError):
            sign_payment(parent.serialize(), 0, [Output(9_900, b"\x51")], 100, key, wrong_signature)
        self.assertEqual(len(calls), 1)

    def test_payment_vectors_are_reproducible(self):
        path = Path(__file__).resolve().parents[1] / "template" / "vectors.json"
        self.assertEqual(json.loads(path.read_text()), vector_document())


if __name__ == "__main__":
    unittest.main()

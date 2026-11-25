from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from shared.one_time_signer import KeyAlreadyUsed, durable_signer


class OneTimeSignerTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "wallet.db"
        self.digest = bytes(32)

    def test_commit_occurs_before_callback_and_survives_callback_error(self):
        def callback(_digest):
            with self.assertRaises(KeyAlreadyUsed):
                durable_signer(self.path, "lamport", b"key", self.fail)(self.digest)
            raise RuntimeError("uncertain signer failure")

        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            durable_signer(self.path, "lamport", b"key", callback)(self.digest)
        with self.assertRaises(KeyAlreadyUsed):
            durable_signer(self.path, "lamport", b"key", self.fail)(self.digest)

    def test_concurrent_requests_share_one_reservation(self):
        def request(_):
            try:
                return durable_signer(self.path, "wots", b"key", lambda digest: digest)(self.digest)
            except KeyAlreadyUsed:
                return None

        with ThreadPoolExecutor(4) as pool:
            results = list(pool.map(request, range(8)))
        self.assertEqual(results.count(self.digest), 1)
        self.assertEqual(results.count(None), 7)

    def test_invalid_digest_does_not_consume_key_and_new_key_can_sign(self):
        sign = durable_signer(self.path, "wots", b"key", lambda digest: digest)
        with self.assertRaisesRegex(ValueError, "32-byte"):
            sign(b"invalid")
        self.assertEqual(sign(self.digest), self.digest)
        other = durable_signer(self.path, "wots", b"new-key", lambda digest: digest)
        self.assertEqual(other(self.digest), self.digest)

"""Wallet security regression tests with disposable keys and local SQLite histories."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import Script, Tx, TxIn, TxOut

from checked_wallet import SigningKeyBlocked, sign_spend
from handwritten import locking_script
from test_native import TRUE, child, signer


class CheckedWalletTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "history.sqlite"
        self.key, self.pub, owner = signer()
        # Use output index 1 to ensure fee/amount and template come from the referenced output.
        lock = locking_script(owner, (0x41, 0x63), version=7)
        self.parent = Tx(1, [TxIn("33" * 32, 0, Script())], [TxOut(5, TRUE), TxOut(1000, lock)], 0)
        self.tx = Tx(2, [TxIn(self.parent.id(), 1, Script())], [TxOut(900, TRUE)], 0)

    def signature(self, digest):
        der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def finish(self, callback, tx=None, flag=0x41, pub=None):
        return sign_spend(self.tx if tx is None else tx, 0, self.parent, flag,
                          self.pub if pub is None else pub, callback, self.path).raw_serialize()

    def test_retry_and_concurrent_observation(self):
        # Concurrent handles run independent compare-and-record transactions.
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.finish(self.signature), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], self.finish(self.signature))
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM seen_r").fetchone()[0], 1)

    def test_alert_persists_and_other_key_is_unaffected(self):
        self.finish(self.signature)
        # Simulate a pre-existing conflicting observation in the disposable ledger.
        # The signer only produces ordinary signatures; no reused nonce is generated.
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE seen_r SET digest=?", (sha256(b"synthetic past observation").digest(),))
        with self.assertRaises(SigningKeyBlocked):
            self.finish(self.signature)
        with self.assertRaises(SigningKeyBlocked):
            self.finish(lambda _: self.fail("blocked key reached the signer"))
        self.key, self.pub, owner = signer(19)
        self.parent = Tx(1, [TxIn("55"*32, 0, Script())], [TxOut(1000, locking_script(owner, version=7))], 0)
        self.tx = child([self.parent], [900])
        self.finish(self.signature)

    def test_verify_before_record(self):
        with self.assertRaises(InvalidSignature):
            self.finish(lambda _: self.signature(sha256(b"different digest").digest()))
        with self.assertRaises(ValueError):
            self.finish(lambda _: bytes(64))
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM seen_r").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM blocked_keys").fetchone()[0], 0)

    def test_preflight_before_signer(self):
        def never(_):
            self.fail("failed preflight reached signer")

        bad = Tx(2, [TxIn("00" * 32, 1, Script())], [TxOut(900, TRUE)], 0)
        for kwargs in (dict(flag=0x42), dict(pub=signer(19)[1]), dict(tx=bad)):
            with self.assertRaises(ValueError):
                self.finish(never, **kwargs)

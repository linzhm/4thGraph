"""BIP340 interoperability and current-input authorization checks."""

import csv
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import unittest

from coincurve import PrivateKey, PublicKeyXOnly

from bip340 import FIELD, lift_x, to_bytes, verify
from payment import lock_for_public_key, sign_payment, sign_spend
from schnorr_script import compiled_template, lock_for_owner, owner_hash, recognize, verifier
from shared.benchmark_validation import Node, chain_verdict
from shared.evaluate import ScriptError, evaluate
from shared.script import push
from shared.transaction import CHRONICLE, Input, Output, Transaction

VECTORS = Path(__file__).resolve().parents[1] / "template" / "bip340-vectors.csv"
MODES = (0x41, 0x42, 0x43, 0x61, 0x62, 0x63, 0xC1, 0xC2, 0xC3, 0xE1, 0xE2, 0xE3)


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
        self.assertEqual(sha256(VECTORS.read_text(encoding="ascii").encode("ascii")).hexdigest(),
                         "01c8cabba63b4c9b2f44c975902990086a4fe56eee9d265b187d1e2c1d98ccfb")
        with VECTORS.open(newline="") as file:
            rows = list(csv.DictReader(file))
        self.assertEqual([int(row["index"]) for row in rows], list(range(19)))
        for row in rows:
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

    def test_untrusted_coordinates_and_exact_encodings(self):
        public = self.public_keys[0]
        message = bytes(32)
        signature = self.keys[0].sign_schnorr(message, aux_randomness=bytes(32))
        y = lift_x(public)[1]
        nonce_y = lift_x(signature[:32])[1]
        for case, unlock in (
            ("odd public ordinate", detached_unlock(message, public, signature, y=FIELD - y)),
            ("off-curve public ordinate", detached_unlock(message, public, signature, y=(y + 2) % FIELD)),
            ("noncanonical public ordinate", detached_unlock(message, public, signature, y=FIELD)),
            ("odd nonce ordinate", detached_unlock(message, public, signature, nonce_y=FIELD - nonce_y)),
            ("wrong even nonce ordinate", detached_unlock(message, public, signature, nonce_y=(nonce_y + 2) % FIELD)),
            ("short signature", detached_unlock(message, public, signature[:-1])),
            ("extra stack item", push(b"extra") + detached_unlock(message, public, signature)),
        ):
            with self.subTest(case=case):
                self.check_detached(unlock, False)

    def sign_two_inputs(self, tx, sighash):
        for i, (parent, public, key) in enumerate(zip(self.parents, self.public_keys, self.keys, strict=True)):
            tx = sign_spend(tx, i, parent.serialize(), public,
                            lambda message: key.sign_schnorr(message, aux_randomness=bytes(32)),
                            sighash=sighash, chronicle_active=bool(sighash & CHRONICLE))
        return tx

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
        with self.assertRaisesRegex(ValueError, "invalid BIP340 signature"):
            sign_payment(parent, 1, (target,), 100, public, lambda _: bytes(64))

        def unexpected(_):
            self.fail("invalid payment reached the signer")

        with self.assertRaisesRegex(ValueError, "balance"):
            sign_payment(parent, 1, (target,), 99, public, unexpected)
        with self.assertRaisesRegex(ValueError, "active spend context"):
            sign_spend(self.unsigned, 0, parent, public, unexpected, sighash=0x61)
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
        self.assertEqual(recognize(raw), owner)


if __name__ == "__main__":
    unittest.main()

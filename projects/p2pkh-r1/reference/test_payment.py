"""Offline fixtures for the pinned BSV node. All signing keys here are public test data."""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import requests
from tx_engine import Script, Tx, TxIn, TxOut

from assemble import assemble
from p2pkh_r1 import locking_script_from_owner_hash, public_key_hash160, recognize
from signature import UNIVERSAL_FLAGS, authorization, current_input_unlock
from wallet import sign_payment

TRUE = Script.parse_string("OP_1")


def locking_script(owner):
    script = Script()
    script.append_data(locking_script_from_owner_hash(owner))
    return script


def signer(scalar):
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return key, pub, public_key_hash160(pub)


def parent(lock, amount, tag):
    return Tx(2, [TxIn(tag * 32, 0, Script())], [TxOut(amount, lock)], 0)


def child(parents, amounts, witnesses=None):
    witnesses = witnesses or {}
    return Tx(2, [TxIn(p.id(), 0, witnesses.get(i, Script())) for i, p in enumerate(parents)],
              [TxOut(a, TRUE) for a in amounts], 0)


def fixture_signature(key, digest):
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def check(tx, parents, ix, valid=True):
    out = parents[ix].tx_outs[tx.tx_ins[ix].prev_index]
    cookie = Path(os.environ["REGTEST_COOKIE"]).read_text().strip().split(":", 1)
    flags = sum(1 << b for b in (1, 2, 3, 16, 18, 19, 20, 21))
    request = dict(tx=tx.serialize().hex(), n=ix, flags=flags, reportflags=True,
                   txo=dict(lock=out.script_pubkey.raw_serialize().hex(), value=out.amount, height=3))
    r = requests.post("http://127.0.0.1:18443", auth=tuple(cookie), timeout=30,
                      json=dict(jsonrpc="1.0", id=1, method="verifyscript", params=[[request], False, 5000]))
    data = r.json()
    if data.get("error"):
        raise AssertionError(data["error"])
    answer = data["result"][0]
    if answer["result"] != ("ok" if valid else "error"):
        raise AssertionError((valid, answer))
    if answer["flags"] & flags != flags:
        raise AssertionError(("missing verification flags", answer))


class CurrentInputTests(unittest.TestCase):
    def test_assembly(self):
        for owner in (bytes(range(20)), bytes([0x11]) * 20, signer(1)[2]):
            self.assertEqual(assemble(owner), locking_script_from_owner_hash(owner))

    def test_consecutive_payments(self):
        ka, qa, ha = signer(7)
        kb, qb, hb = signer(19)
        lock_a = locking_script(ha)
        lock_b = locking_script(hb)
        self.assertEqual(recognize(lock_a.raw_serialize()), ha)
        prior = Tx(2, [TxIn("77" * 32, 0, Script())],
                   [TxOut(75, TRUE), TxOut(100_000, lock_a)], 0)
        vout = 1
        child_sizes = []
        with TemporaryDirectory() as directory:
            for hop, (key, pub, dest) in enumerate(((ka, qa, lock_b), (kb, qb, lock_a),
                                                    (ka, qa, lock_b)), start=1):
                amount = prior.tx_outs[vout].amount
                signed = sign_payment(prior, vout, [TxOut(amount - 1000, dest)], 1000,
                                      pub, lambda digest: fixture_signature(key, digest),
                                      Path(directory) / "history.sqlite")
                check(signed, [prior], 0)
                raw = signed.tx_ins[0].script_sig.raw_serialize()
                # Four pushes and one selector, with no space for a parent, its
                # scriptSig or an earlier R1 signature. Verify each push boundary.
                self.assertEqual(raw[:2], bytes((76, 159)))
                self.assertEqual(raw[161], 65)
                self.assertEqual(raw[162:227], pub)
                self.assertEqual(raw[227], 64)
                self.assertEqual(raw[292], 32)
                self.assertEqual(raw[325:], bytes(1))
                self.assertEqual((signed.tx_ins[0].prev_tx, signed.tx_ins[0].prev_index),
                                 (prior.id(), vout))
                self.assertNotIn(prior.serialize(), raw)
                if hop > 1:
                    self.assertNotIn(prior.tx_ins[0].script_sig.raw_serialize()[228:292], raw)
                child_sizes.append(len(signed.serialize()))
                print("CURRENT_INPUT_HOP", hop, "lock", len(dest.raw_serialize()),
                      "unlock", len(raw), "child", child_sizes[-1], flush=True)
                prior, vout = signed, 0
        self.assertEqual(len(set(child_sizes)), 1)

    def test_sig_types(self):
        key, pub, owner = signer(7)
        lock = locking_script(owner)
        parents = [parent(TRUE, 400, "22"), parent(lock, 1000, "33")]
        for paired in (True, False):
            amounts = [600, 600] if paired else [900]
            for flag in UNIVERSAL_FLAGS if paired else (0x43, 0xc3, 0x63, 0xe3):
                with self.subTest(paired=paired, flag=hex(flag)):
                    unsigned = child(parents, amounts)
                    auth = authorization(unsigned, 1, 1000, flag)
                    witness = current_input_unlock(auth, pub, fixture_signature(key, auth.digest()))
                    tx = child(parents, amounts, {1: witness})
                    check(tx, parents, 1)
                    if auth.companion:
                        self.assertEqual(len(auth.preimage), 163)
                    tx.validate(parents)
                    if paired:
                        # Re-use the approval after changing the paired amount:
                        # ALL/SINGLE cover it, NONE intentionally leaves it free.
                        check(child(parents, [600, 599], {1: witness}), parents, 1,
                              valid=(flag & 31 == 2))
                    else:
                        changed_parent = parent(lock, 1000, "44")
                        different = [parents[0], changed_parent]
                        check(child(different, amounts, {1: witness}), different, 1, False)

    def test_signing_vector(self):
        key, pub, owner = signer(1)
        funding = parent(locking_script(owner), 1000, "22")
        unsigned = child([funding], [900])
        auth = authorization(unsigned, 0, 1000, 0x41)
        sig = fixture_signature(key, auth.digest())
        unlocking = current_input_unlock(auth, pub, sig)
        signed = child([funding], [900], {0: unlocking})
        check(signed, [funding], 0)
        signed.validate([funding])
        vector = dict(type="41", input_index=0, previous_amount_sats=1000,
                      parent_txid=funding.id(), unsigned_tx_hex=unsigned.serialize().hex(),
                      owner_hash160=owner.hex(), public_key_x963=pub.hex(), preimage_hex=auth.preimage.hex(),
                      digest_hex=auth.digest().hex(), signature_hex=sig.hex(),
                      script_sig_hex=unlocking.raw_serialize().hex(), signed_txid=signed.id())
        fixture = Path(__file__).resolve().parents[1] / "template/spend-all.json"
        self.assertEqual(vector, json.loads(fixture.read_text()))

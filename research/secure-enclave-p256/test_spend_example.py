"""Reproducible synthetic single-input payment. The test signer is software-only."""
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import Script, Tx, TxIn, TxOut

from checked_wallet import sign_payment
from p2pkh_r1 import locking_script_from_public_key
from replay_payment import replay
from test_native import signer
from test_universal import check
from universal import authorization, universal_unlocking_script


class OrdinaryPaymentTest(unittest.TestCase):
    def test_public_vector(self):
        parent, signed = replay()
        check(signed, [parent], 0)

    def test_chronicle_all_size(self):
        parent, ordinary = replay()
        key, pub, _ = signer(1)
        unsigned = Tx(2, [TxIn(parent.id(), 0, Script())], ordinary.tx_outs, 0)
        amount = parent.tx_outs[0].amount
        bip143 = authorization(unsigned, 0, amount, 0x41)
        otda = authorization(unsigned, 0, amount, 0x61)
        der = key.sign(otda.digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        unlock = universal_unlocking_script(parent.serialize(), otda, pub, sig)
        chronicle = Tx(2, [TxIn(parent.id(), 0, unlock)], ordinary.tx_outs, 0)
        chronicle.validate([parent])
        check(chronicle, [parent], 0)
        for name, auth, tx in (("BIP143_ALL", bip143, ordinary), ("OTDA_ALL", otda, chronicle)):
            print("CHRONICLE_VECTOR_SIZE", name, "preimage", len(auth.preimage),
                  "unlock", len(tx.tx_ins[0].script_sig.raw_serialize()), "transaction", len(tx.serialize()))

    def test_complete_payment(self):
        key, pubkey, _ = signer(1)  # Public P-256 generator point, for this fixture only.
        parent_lock = Script()
        parent_lock.append_data(locking_script_from_public_key(pubkey))
        parent = Tx(2, [TxIn("22" * 32, 0, Script())], [TxOut(100_000, parent_lock)], 0)
        destination = Script.parse_string(
            "OP_DUP OP_HASH160 0x000102030405060708090a0b0c0d0e0f10111213 OP_EQUALVERIFY OP_CHECKSIG"
        )
        outputs = [TxOut(99_000, destination)]
        unsigned = Tx(2, [TxIn(parent.id(), 0, Script())], outputs, 0)
        auth = authorization(unsigned, 0, 100_000, 0x41)
        calls = []

        def sign_digest(digest):
            self.assertEqual(digest, auth.digest())
            der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
            r, s = utils.decode_dss_signature(der)
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            calls.append(raw)
            return raw

        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "history.sqlite"
            with self.assertRaisesRegex(ValueError, "balance"):
                sign_payment(parent, 0, outputs, 999, pubkey, sign_digest, ledger)
            self.assertFalse(calls)
            signed = sign_payment(parent, 0, outputs, 1_000, pubkey, sign_digest, ledger)
        self.assertEqual(len(calls), 1)
        replayed = Tx.parse(signed.serialize())
        self.assertEqual(replayed.id(), signed.id())
        check(replayed, [parent], 0)
        fixture = {
            "template": "P2PKH-R1",
            "network_context": "offline synthetic prevout, BSV Node 1.2.3 regtest",
            "parent_txid": parent.id(),
            "vout": 0,
            "previous_amount_sats": 100_000,
            "input_index": 0,
            "recipient_amount_sats": 99_000,
            "fee_sats": 1_000,
            "recipient_script_hex": destination.raw_serialize().hex(),
            "unsigned_tx_hex": unsigned.serialize().hex(),
            "requested_type": "41",
            "preimage_type": "41",
            "script_code_hex": "68ac",
            "preimage_hex": auth.preimage.hex(),
            "digest_hex": auth.digest().hex(),
            "public_key_x963": pubkey.hex(),
            "signature_raw_hex": calls[0].hex(),
            "signed_txid": signed.id(),
            "parent_bytes": len(parent.serialize()),
            "unlock_bytes": len(signed.tx_ins[0].script_sig.raw_serialize()),
            "signed_tx_bytes": len(signed.serialize()),
            "expected_input_result": "ok",
        }
        print("ORDINARY_PAYMENT_VECTOR " + json.dumps(fixture, sort_keys=True), flush=True)

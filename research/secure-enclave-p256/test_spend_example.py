"""Reproducible synthetic single-input payment. The test signer is software-only."""
import json
from pathlib import Path
from hashlib import sha256, shake_256
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import Script, Tx, TxIn, TxOut, Wallet

from checked_wallet import sign_payment
from handwritten import GROUP_ORDER_R1
from p2pkh_r1 import locking_script_from_public_key, public_key_hash160, recognize
from replay_payment import replay
from test_native import signer
from test_universal import check
from universal import authorization, universal_unlocking_script


def fixture_signature(key, digest):
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class OrdinaryPaymentTest(unittest.TestCase):
    def test_p2pkh_funds_r1_then_r1_pays_a_new_r1_owner(self):
        # Only the initial UTXO is supplied synthetically. Every subsequent
        # input spends the bytes of the preceding fully signed transaction.
        source = Wallet.from_int("BSV_Testnet", 11)
        source_lock = source.get_locking_script()
        seed = Tx(2, [TxIn("88" * 32, 0, Script())], [TxOut(106_000, source_lock)], 0)
        key_a, pub_a, _ = signer(7)
        key_b, pub_b, _ = signer(19)

        def r1_lock(public_key):
            raw = locking_script_from_public_key(public_key)
            self.assertEqual(recognize(raw), public_key_hash160(public_key))
            script = Script()
            script.append_data(raw)
            return script

        lock_a = r1_lock(pub_a)
        lock_b = r1_lock(pub_b)
        self.assertNotEqual(lock_a.raw_serialize(), lock_b.raw_serialize())
        funding = Tx(2, [TxIn(seed.id(), 0, Script())],
                     [TxOut(5_000, source_lock), TxOut(100_000, lock_a)], 0)
        funding = source.sign_tx_sighash(0, seed, funding, 0x41)
        funding.validate([seed])
        check(funding, [seed], 0)

        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "history.sqlite"
            transfer = sign_payment(funding, 1, [TxOut(99_000, lock_b)], 1_000,
                                    pub_a, lambda digest: fixture_signature(key_a, digest), ledger)
            final = sign_payment(transfer, 0, [TxOut(98_000, source_lock)], 1_000,
                                 pub_b, lambda digest: fixture_signature(key_b, digest), ledger)
        for label, parent, vout, tx in (("A_to_B", funding, 1, transfer),
                                       ("B_to_P2PKH", transfer, 0, final)):
            inp = tx.tx_ins[0]
            self.assertEqual((inp.prev_tx, inp.prev_index), (parent.id(), vout))
            literal = Script()
            literal.append_pushdata(parent.serialize())
            self.assertTrue(inp.script_sig.raw_serialize().startswith(literal.raw_serialize()))
            check(tx, [parent], 0)
            print("R1_CHAIN", label, "parent", parent.id(), "vout", vout,
                  "signed", tx.id(), "parent_bytes", len(parent.serialize()), flush=True)

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
        sig = fixture_signature(key, otda.digest())
        unlock = universal_unlocking_script(parent.serialize(), otda, pub, sig)
        chronicle = Tx(2, [TxIn(parent.id(), 0, unlock)], ordinary.tx_outs, 0)
        chronicle.validate([parent])
        check(chronicle, [parent], 0)
        for name, auth, tx in (("BIP143_ALL", bip143, ordinary), ("OTDA_ALL", otda, chronicle)):
            print("CHRONICLE_VECTOR_SIZE", name, "preimage", len(auth.preimage),
                  "unlock", len(tx.tx_ins[0].script_sig.raw_serialize()), "transaction", len(tx.serialize()))

    def test_functional_bip143_preimage_with_literal_parent(self):
        # Candidate witness encoding for authorized version-2 BIP143 ALL spends.
        # The first item is always a literal full parent. The lock is canonical.
        key, pub, _ = signer(1)
        first, ordinary = replay()
        other = Script.parse_string("OP_1")
        r1 = first.tx_outs[0]
        second = Tx(2, [TxIn("66" * 32, 0, Script()), TxIn("77" * 32, 2, Script())],
                    [r1, TxOut(700, other), r1], 0)
        for parent, vout in ((first, 0), (second, 2)):
            with self.subTest(vout=vout):
                unsigned = Tx(2, [TxIn(parent.id(), vout, Script())], ordinary.tx_outs, 0)
                amount = parent.tx_outs[vout].amount
                auth = authorization(unsigned, 0, amount, 0x41)
                raw_parent = parent.serialize()
                self.assertEqual(auth.preimage[68:100], sha256(sha256(raw_parent).digest()).digest())
                signature = fixture_signature(key, auth.digest())
                baseline = universal_unlocking_script(raw_parent, auth, pub, signature)
                candidate = Script()
                candidate.append_pushdata(raw_parent)
                candidate.append_data(Script.parse_string("OP_DUP OP_HASH256").raw_serialize())
                candidate.append_pushdata(auth.preimage[:68])
                candidate.append_data(Script.parse_string("OP_SWAP OP_CAT").raw_serialize())
                candidate.append_pushdata(auth.preimage[100:])
                candidate.append_data(Script.parse_string("OP_CAT").raw_serialize())
                s = int.from_bytes(signature[32:], "big")
                inverse = pow(s, -1, GROUP_ORDER_R1).to_bytes(32, "little")
                for field in (pub, signature, bytes(4), inverse):
                    candidate.append_pushdata(field)
                candidate.append_byte(0)  # Ordinary selector.
                sizes = []
                for unlock in (baseline, candidate):
                    tx = Tx(2, [TxIn(parent.id(), vout, unlock)], ordinary.tx_outs, 0)
                    tx.validate([parent])
                    check(tx, [parent], 0)
                    sizes.append((len(unlock.raw_serialize()), len(tx.serialize())))
                self.assertEqual(sizes[0][0] - sizes[1][0], 27)
                self.assertEqual(sizes[0][1] - sizes[1][1], 27)
                print("BIP143_FUNCTIONAL_WITNESS", vout, len(raw_parent), sizes, flush=True)

    def test_complete_parent_is_one_literal_push(self):
        key, pubkey, _ = signer(1)
        lock = Script()
        lock.append_data(locking_script_from_public_key(pubkey))
        other = Script.parse_string("OP_1")
        outputs = [TxOut(99_000, other)]

        def make_parent(prev_outputs, payload):
            previous_unlock = Script()
            previous_unlock.append_pushdata(payload)
            inputs = [TxIn("33" * 32, 1, previous_unlock), TxIn("44" * 32, 0, Script())]
            return Tx(2, inputs, prev_outputs, 7)

        prev_outputs = [TxOut(700, other), TxOut(100_000, lock)]
        payload = shake_256(b"public fixture bytes").digest(8000)
        size_at_512 = len(make_parent(prev_outputs, payload[:512]).serialize())
        boundary_payload = 512 + 65535 - size_at_512
        cases = [
            (make_parent(prev_outputs, payload[:boundary_payload]), 1, 65535, 0x4d, 2),
            (make_parent(prev_outputs, payload[:boundary_payload + 1]), 1, 65536, 0x4e, 4),
            # Two identical R1 scripts. Spend the last of 253 outputs.
            (make_parent([TxOut(350, lock)] + [TxOut(1, other)] * 251 + [TxOut(100_000, lock)],
                         payload[:300]), 252, None, 0x4e, 4),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for parent, vout, size, opcode, width in cases:
                with self.subTest(vout=vout, size=size):
                    raw = parent.serialize()
                    if size is not None:
                        self.assertEqual(len(raw), size)
                    signed = sign_payment(parent, vout, outputs, 1_000, pubkey,
                                          lambda digest: fixture_signature(key, digest),
                                          Path(directory) / "history.sqlite")
                    script = signed.tx_ins[0].script_sig.raw_serialize()
                    self.assertEqual(script[0], opcode)
                    self.assertEqual(int.from_bytes(script[1:1 + width], "little"), len(raw))
                    start = 1 + width
                    self.assertEqual(script[start:start + len(raw)], raw)
                    check(signed, [parent], 0)

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
            raw = fixture_signature(key, digest)
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

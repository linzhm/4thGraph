"""Offline input-level conformance for the current-transaction-only payment lock."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tx_engine import Script, Tx, TxIn, TxOut

from checked_wallet import sign_payment
from handwritten import UNIVERSAL_FLAGS, locking_script, match_locking_script
from test_native import TRUE, child, parent, signer
from test_spend_example import fixture_signature
from test_universal import check
from universal import authorization, current_input_unlock


class CurrentInputTests(unittest.TestCase):
    def test_consecutive_payments(self):
        ka, qa, ha = signer(7)
        kb, qb, hb = signer(19)
        lock_a = locking_script(ha, version=9)
        lock_b = locking_script(hb, version=9)
        self.assertEqual(match_locking_script(lock_a.raw_serialize()).owner_hash160, ha)
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
        lock = locking_script(owner, version=9)
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
                        with self.assertRaisesRegex(ValueError, "Top of stack is false"):
                            tx.validate(parents)
                    else:
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

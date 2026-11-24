from dataclasses import replace
from hashlib import sha256
import unittest

from continuity_preimage import current_funding_hash, prior_digest, prior_preimage
from continuity_statement import ParentReceipt
from shared.evaluate import ScriptError, evaluate
from shared.script import push
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_all
from transfer import COMPACT_SCRIPTCODE


class ContinuityPreimageTests(unittest.TestCase):
    def setUp(self):
        self.funding = Transaction((Input(b"f" * 32, 2, push(b"seed"), sequence=123),),
                                   (Output(9_654_321, b"\x51" * 260),), locktime=456)
        self.funding_hash = sha256(blob(self.funding.outputs[0].script)).digest()
        self.asset_id, self.key_digest = b"a" * 32, b"k" * 32

    def prior(self, count):
        receipt = ParentReceipt(tuple(bytes([i + 1]) * 32 for i in range(count)))
        first = Input(self.funding.txid_wire(), 0, push(bytes(70000)), sequence=123)
        extras = tuple(Input(bytes([i + 8]) * 32, i, push(b"parent token"), sequence=700 + i)
                       for i in range(max(1, count)))
        tx = Transaction((first, *extras), (Output(1000, b"\x51"), Output(900, b"\x52"), receipt.output()),
                         version=3, locktime=567)
        return tx, receipt

    def script(self, tx, funding=None, lock_hash=None):
        return b"".join(push(part) for part in (
            tx.serialize(), (funding or self.funding).serialize(), lock_hash or self.funding_hash,
        ))

    def test_prior_and_current_reconstruct_exact_forkid(self):
        for count in range(3):
            with self.subTest(count=count):
                tx, receipt = self.prior(count)
                preimage = preimage_all(tx, 0, self.funding.outputs[0].value, COMPACT_SCRIPTCODE)
                self.assertEqual(evaluate(self.script(tx) + prior_preimage()), ([receipt.payload(), preimage], []))
                expected = receipt.digest(self.asset_id, self.key_digest, hash256(preimage))
                self.assertEqual(evaluate(self.script(tx) + prior_digest(self.asset_id, self.key_digest)),
                                 ([expected], []))
                self.assertEqual(evaluate(push(self.funding.serialize()) + push(preimage) + current_funding_hash()),
                                 ([self.funding_hash], []))

    def test_rejects_wrong_lock_outpoint_amount_and_receipt_shape(self):
        tx, _ = self.prior(2)
        preimage = preimage_all(tx, 0, self.funding.outputs[0].value + 1, COMPACT_SCRIPTCODE)
        with self.assertRaises(ScriptError):
            evaluate(push(self.funding.serialize()) + push(preimage) + current_funding_hash())
        for raw in (
            self.script(tx, lock_hash=b"x" * 32),
            self.script(tx, funding=replace(self.funding, locktime=321)),
            self.script(replace(tx, outputs=(*tx.outputs[:2], ParentReceipt((b"x" * 32,)).output()))),
            self.script(replace(tx, outputs=(*tx.outputs[:2], replace(tx.outputs[-1], value=1)))),
            self.script(replace(tx, outputs=(*tx.outputs[:2], replace(tx.outputs[-1], script=tx.outputs[-1].script + b"\x00")))),
        ):
            with self.assertRaises(ScriptError):
                evaluate(raw + prior_preimage())

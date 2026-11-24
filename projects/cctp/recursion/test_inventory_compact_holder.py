from dataclasses import replace
from importlib.util import find_spec
import unittest

from inventory_payment import companion_lock, companion_witness, token_output, token_parts, token_witness
from inventory_tree import InventoryState
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


@unittest.skipUnless(find_spec("tx_engine"), "requires the independent chain-gang evaluator")
class CompactInventoryHolderTests(unittest.TestCase):
    def setUp(self):
        verifier = Transaction((Input(b"v"*32, 0),), (Output(1000, asm("OP_1")),))
        coupon = Input(b"c"*32, 4)
        self.companion = Transaction((coupon,), (Output(1000, companion_lock(verifier)),))
        self.owner, self.sign = fixture_signer(19)
        parts = token_parts(hash256(b"inventory compact holder"), (coupon.outpoint(),), compact_holder=True)
        self.previous = token_output(InventoryState(107, 1000, self.owner), parts)
        origins = tuple(Transaction((Input(bytes([n])*32, 0),), (self.previous,)) for n in (3, 4))
        self.parents = (verifier, self.companion, *origins)
        self.tx = Transaction(tuple(Input(p.txid_wire(), 0) for p in self.parents), (self.previous, self.previous))

    def signed(self, tx):
        result = tx.with_script(1, companion_witness(tx, self.companion))
        for vin in (2, 3):
            result = result.with_script(vin, token_witness(tx, vin, self.previous, self.companion,
                                                        self.sign, compact_holder=True))
        return result

    def check(self, tx):
        from shared.chain_gang import validate_at_heights
        validate_at_heights(tx, self.parents, spend_height=100, activation_height=2, utxo_heights=[3]*4)

    def test_full_lock_holder_and_suffix_only_binding(self):
        captured = []
        def signer(digest):
            captured.append(digest)
            return self.sign(digest)
        witness = token_witness(self.tx, 2, self.previous, self.companion, signer, compact_holder=True)
        full = preimage_all(self.tx, 2, self.previous.value, self.previous.script)
        compact = preimage_all(self.tx, 2, self.previous.value, COMPACT_SCRIPTCODE)
        self.assertEqual(captured, [hash256(full)])
        self.assertTrue(witness.endswith(push(compact)))
        self.assertNotIn(full, witness)
        self.assertEqual(len(compact), 192)
        self.check(self.signed(self.tx))

    def test_holder_rejects_stale_and_forged_binding_with_new_signature(self):
        tx = replace(self.tx, locktime=1)
        signed = self.signed(tx)
        raw = preimage_all(tx, 2, self.previous.value, COMPACT_SCRIPTCODE)
        stale = preimage_all(self.tx, 2, self.previous.value, COMPACT_SCRIPTCODE)
        full = preimage_all(tx, 2, self.previous.value, self.previous.script)
        prevouts = b"".join(i.outpoint() for i in tx.inputs)
        other_companion = replace(self.companion, locktime=2)
        vector = prevouts[:36] + Input(other_companion.txid_wire(), 0).outpoint() + prevouts[72:]
        # The alternate companion names the right coupon and even matches the
        # supplied vector and its hash. The actual transaction binding must fail.
        altered = raw[:4] + hash256(vector) + raw[36:]
        cases = (
            (self.sign(hash256(full)), self.companion, prevouts, stale),
            (self.sign(hash256(raw)), self.companion, prevouts, raw),
            (fixture_signer(18)[1](hash256(full)), self.companion, prevouts, raw),
            (self.sign(hash256(full)), other_companion, prevouts, raw),
            (self.sign(hash256(full)), other_companion, vector, altered),
            (self.sign(hash256(full)), self.companion, prevouts, full),
        )
        for i, (sig, companion, points, preimage) in enumerate(cases):
            with self.subTest(case=i), self.assertRaises(ValueError):
                witness = b"".join(map(push, (sig+b"\x41", companion.serialize(), points, preimage)))
                self.check(signed.with_script(2, witness))

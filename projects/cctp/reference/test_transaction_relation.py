from dataclasses import replace
import unittest

from shared.pushtx import PUBLIC
from shared.script import asm
from shared.transaction import Input, Output, Transaction, preimage_all
from statement import AssetDescriptor, Slot
from transaction_relation import TokenState, bind_transfer, read_token, token_lock
from transfer import COMPACT_SUFFIX, COMPACT_SCRIPTCODE


class TransactionRelationTests(unittest.TestCase):
    def setUp(self):
        self.asset = AssetDescriptor(1, b'a' * 36, 6, 7, b'r' * 32, b'p' * 32)
        self.lock = asm('OP_1') + COMPACT_SUFFIX  # Shape fixture, not a proof verifier.
        self.state = TokenState(self.asset.asset_id(), 1024, PUBLIC)
        self.verifier = Transaction((Input(b'f' * 32, 0),), (Output(1, self.lock),))
        self.parent = Transaction((Input(b'p' * 32, 0),),
                                  (Output(1, b'\x51'), Output(2, token_lock(self.state, self.lock))))
        self.tx = Transaction((Input(self.verifier.txid_wire(), 0), Input(self.parent.txid_wire(), 1)),
                              tuple(Output(1, token_lock(replace(self.state, quantity=q), self.lock))
                                    for q in (640, 384)))
        self.parents = (self.verifier.serialize(), self.parent.serialize())
        self.inputs = (Slot(1, 1024),)
        self.outputs = (Slot(0, 640), Slot(1, 384))

    def bind(self, **changes):
        args = dict(asset=self.asset, verifier_key_id=b'k' * 32, tx=self.tx,
                    parent_bytes=self.parents, verifier_lock=self.lock,
                    inputs=self.inputs, outputs=self.outputs,
                    authenticated_preimage=preimage_all(self.tx, 0, 1, COMPACT_SCRIPTCODE))
        return bind_transfer(**(args | changes))

    def test_split_and_independent_parent_mimo(self):
        bound = self.bind()
        self.assertEqual(tuple(s.quantity for s in bound.input_states), (1024,))
        self.assertEqual(tuple(s.quantity for s in bound.output_states), (640, 384))
        other = replace(self.parent, locktime=1, outputs=(Output(1, token_lock(
            replace(self.state, quantity=384), self.lock)),))
        first = replace(self.parent, outputs=(Output(1, token_lock(
            replace(self.state, quantity=640), self.lock)),))
        tx = replace(self.tx, inputs=(self.tx.inputs[0], Input(first.txid_wire(), 0),
                                     Input(other.txid_wire(), 0)))
        self.bind(tx=tx, parent_bytes=(self.parents[0], first.serialize(), other.serialize()),
                  inputs=(Slot(1, 640), Slot(2, 384)),
                  authenticated_preimage=preimage_all(tx, 0, 1, COMPACT_SCRIPTCODE))

    def test_parent_position_and_preimage_mutations(self):
        for change in (
            dict(parent_bytes=(self.parents[0], replace(self.parent, locktime=1).serialize())),
            dict(parent_bytes=self.parents[:1]),
            dict(parent_bytes=(self.parents[0], self.parents[1] + b'\0')),
            dict(tx=replace(self.tx, inputs=(self.tx.inputs[0], Input(self.parent.txid_wire(), 0)))),
            dict(tx=replace(self.tx, outputs=self.tx.outputs[::-1])),
            dict(authenticated_preimage=b'\0' * 192),
            dict(inputs=(Slot(1, 1023),)),
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.bind(**change)

    def test_forged_omitted_and_wrong_successor_locks(self):
        variants = [
            (Output(1, b'\x51'), self.tx.outputs[1]),
            (Output(1, token_lock(replace(self.state, quantity=640, frozen=True), self.lock)), self.tx.outputs[1]),
            (Output(1, token_lock(replace(self.state, quantity=640, asset_id=b'x' * 32), self.lock)), self.tx.outputs[1]),
            (Output(1, token_lock(replace(self.state, quantity=640), self.lock) + b'\x51'), self.tx.outputs[1]),
            self.tx.outputs + (Output(1, token_lock(replace(self.state, quantity=1), self.lock)),),
        ]
        for outputs in variants:
            tx = replace(self.tx, outputs=outputs)
            with self.subTest(outputs=outputs), self.assertRaises(ValueError):
                self.bind(tx=tx, authenticated_preimage=preimage_all(tx, 0, 1, COMPACT_SCRIPTCODE))

    def test_omitted_input_and_duplicate_input(self):
        tx = replace(self.tx, inputs=self.tx.inputs + (Input(self.parent.txid_wire(), 1),))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.bind(tx=tx, parent_bytes=self.parents + (self.parents[1],))
        parent = replace(self.parent, locktime=2)
        tx = replace(self.tx, inputs=self.tx.inputs + (Input(parent.txid_wire(), 1),))
        with self.assertRaisesRegex(ValueError, 'declared slots'):
            self.bind(tx=tx, parent_bytes=self.parents + (parent.serialize(),),
                      authenticated_preimage=preimage_all(tx, 0, 1, COMPACT_SCRIPTCODE))

    def test_canonical_metadata_and_satoshi_independence(self):
        script = token_lock(self.state, self.lock)
        self.assertEqual(read_token(script, self.lock), self.state)
        for broken in (script[:-1], script + b'\0', script.replace(bytes([74]), b'\x4c\x4a', 1)):
            with self.assertRaises(ValueError):
                read_token(broken, self.lock)
        tx = replace(self.tx, outputs=tuple(replace(o, value=2) for o in self.tx.outputs))
        self.bind(tx=tx, authenticated_preimage=preimage_all(tx, 0, 1, COMPACT_SCRIPTCODE))

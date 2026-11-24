from dataclasses import replace
import unittest

from shared.transaction import Input, Output, Transaction
from statement import AssetDescriptor, Slot, public_inputs, transfer_bytes


class StatementTests(unittest.TestCase):
    def setUp(self):
        self.asset = AssetDescriptor(1, bytes(range(36)), 6, 7, b"a" * 32, b"p" * 32)
        self.parent = Transaction((Input(b"f" * 32, 0),), (Output(1, b"\x51"),))
        self.tx = Transaction(
            (Input(self.parent.txid_wire(), 0), Input(b"t" * 32, 2)),
            (Output(1, b"\x51"), Output(1, b"\x52")),
        )
        self.inputs = (Slot(1, 1024),)
        self.outputs = (Slot(0, 640), Slot(1, 384))

    def statement(self, **changes):
        args = dict(asset=self.asset, verifier_key_id=b"k" * 32, tx=self.tx,
                    verifier_parent=self.parent, verifier_lock=b"\x51",
                    inputs=self.inputs, outputs=self.outputs)
        return transfer_bytes(**(args | changes))

    def test_vector(self):
        self.assertEqual(public_inputs(self.statement()), VECTOR)

    def test_transaction_and_policy_binding(self):
        original = public_inputs(self.statement())
        variants = (
            dict(asset=replace(self.asset, network=2)),
            dict(verifier_key_id=b"o" * 32),
            dict(tx=replace(self.tx, outputs=self.tx.outputs[::-1])),
            dict(tx=replace(self.tx, inputs=(self.tx.inputs[0], Input(b"x" * 32, 2)))),
            dict(outputs=(Slot(0, 384), Slot(1, 640))),
        )
        for changes in variants:
            with self.subTest(changes=changes):
                self.assertNotEqual(public_inputs(self.statement(**changes)), original)

    def test_rejected_statements(self):
        variants = (
            dict(verifier_lock=b"\x52"),
            dict(inputs=(Slot(0, 1024),)),
            dict(outputs=(Slot(0, 640), Slot(0, 384))),
            dict(outputs=(Slot(0, 640), Slot(1, 385))),
            dict(outputs=(Slot(0, 1024), Slot(1, 0))),
            dict(tx=replace(self.tx, inputs=(self.tx.inputs[0],) * 2)),
        )
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.statement(**changes)


VECTOR = (136881323057367600158502994991741514241, 112277488447274794075149848190267146273)

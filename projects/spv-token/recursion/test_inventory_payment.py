from dataclasses import replace
import unittest

from chronicle_preimage import CHRONICLE_ALL
from inventory_payment import payment_rules, token_output, token_parts, verifier_witness
from inventory_tree import InventoryLeaf, InventoryState, inventory_root, membership_path, payment_digest
from shared.evaluate import ScriptError, evaluate
from shared.script import push
from shared.transaction import Input, Transaction, hash256, preimage_otda
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


class InventoryPaymentRulesTests(unittest.TestCase):
    def setUp(self):
        self.scope = hash256(b"inventory experiment")
        self.parts = token_parts(self.scope, (bytes(36),))
        self.leaves = tuple(
            InventoryLeaf(self.scope, Input(bytes([i])*32, i % 2).outpoint(),
                          InventoryState(quantity, 1000, fixture_signer(15+i)[0]))
            for i, quantity in enumerate((101, 203, 307, 409)))
        self.root = inventory_root(self.leaves)

    def material(self, selection, outputs, openings=None):
        selected = [self.leaves[i] for i in selection]
        tx = Transaction((Input(b"W"*32, 0), Input(b"T"*32, 0), *(
            Input(l.outpoint[:32], int.from_bytes(l.outpoint[32:], "little")) for l in selected)),
            tuple(token_output(state, self.parts) for state in outputs))
        return tx, [(i, membership_path(self.leaves, i), self.leaves[i].state)
                    for i in (selection if openings is None else openings)]

    def execute(self, tx, outputs, openings, *, private=False):
        proof = push(b"origin proof placeholder")
        expected = [b"origin proof placeholder"]
        optional = {}
        if private:
            optional["payment_witness"] = push(b"payment proof placeholder")
            expected.append(b"payment proof placeholder")
        else:
            optional["openings"] = openings
        unlock = verifier_witness(tx, self.root, proof, outputs, **optional)
        stack, alt = evaluate(unlock + payment_rules(self.scope, self.parts, private_membership=private))
        digest = hash256(preimage_otda(tx, 0, COMPACT_SCRIPTCODE, CHRONICLE_ALL))
        self.assertEqual(alt, [bytes([CHRONICLE_ALL]), digest])
        expected.append(self.root)
        if private:
            expected.append(payment_digest(self.scope, self.root, [i.outpoint() for i in tx.inputs[2:]], outputs))
        self.assertEqual(stack, expected)

    def test_same_root_different_subsets_and_receivers(self):
        for selection in ((0, 2), (1, 3), (2, 0)):
            x, y = (self.leaves[i].state for i in selection)
            outputs = (replace(x, quantity=x.quantity+5, sats=950, owner=y.owner),
                       replace(y, quantity=y.quantity-5, sats=1050))
            tx, openings = self.material(selection, outputs)
            for private in (False, True):
                self.execute(tx, outputs, openings, private=private)

    def test_uint64_conserved_total_boundary(self):
        maximum = (1 << 64) - 1
        for large in (maximum - 1, maximum):
            with self.subTest(large_quantity=large):
                amounts = (large, 100, 1, 2)
                self.leaves = tuple(replace(leaf, state=replace(leaf.state, quantity=amount))
                                    for leaf, amount in zip(self.leaves, amounts, strict=True))
                self.root = inventory_root(self.leaves)
                outputs = (self.leaves[0].state, self.leaves[2].state)
                tx, openings = self.material((0, 2), outputs)
                if large == maximum:
                    with self.assertRaises(ScriptError):
                        self.execute(tx, outputs, openings)
                else:
                    self.execute(tx, outputs, openings)

    def test_invalid_positions_states_sums_and_actual_outputs(self):
        outputs = (self.leaves[0].state, self.leaves[2].state)
        tx, openings = self.material((0, 2), outputs)
        for selection, outs, supplied in (
            ((0, 0), outputs, (0, 2)), ((0, 2), outputs, (2, 0)),
            ((0, 2), (replace(outputs[0], quantity=99), outputs[1]), (0, 2)),
            ((0, 2), (replace(outputs[0], sats=999), outputs[1]), (0, 2)),
            ((0, 2), (replace(outputs[0], frozen=True), outputs[1]), (0, 2)),
        ):
            with self.subTest(selection=selection, outs=outs, supplied=supplied), self.assertRaises(ScriptError):
                altered, paths = self.material(selection, outs, supplied)
                self.execute(altered, outs, paths)
        for private in (False, True):
            with self.assertRaises(ScriptError):
                self.execute(replace(tx, outputs=tx.outputs[::-1]), outputs, openings, private=private)

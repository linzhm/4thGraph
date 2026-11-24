from dataclasses import replace
from random import Random
import unittest

from chronicle_preimage import CHRONICLE_ALL
from inventory_payment import token_output, token_parts
from inventory_tree import InventoryLeaf, InventoryState, inventory_root
from inventory_wide import wide_rules, wide_witness
from shared.evaluate import ScriptError, evaluate
from shared.script import push
from shared.transaction import Input, Transaction, hash256, preimage_all, preimage_otda
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


class WideInventoryPaymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = hash256(b"small inventory E test")
        cls.parts = token_parts(cls.scope, (bytes(36),), input_count=66)
        owner = fixture_signer(31)[0]
        cls.leaves = tuple(
            InventoryLeaf(cls.scope, Input(hash256(bytes([i])), i % 7).outpoint(), InventoryState(i+1, 1000, owner))
            for i in range(128))
        cls.root = inventory_root(cls.leaves)
        cls.rules = wide_rules(cls.scope, cls.parts, cls.root)
        cls.compact = wide_rules(cls.scope, cls.parts, cls.root, compact_outputs=True)
        cls.verifier_sats = 20000

    def shape(self, positions, leaves=None):
        leaves = self.leaves if leaves is None else leaves
        selected = [leaves[i] for i in positions]
        inputs = (Input(b"W"*32, 0), Input(b"C"*32, 0), *(
            Input(leaf.outpoint[:32], int.from_bytes(leaf.outpoint[32:], "little")) for leaf in selected))
        outputs = tuple(leaf.state for leaf in reversed(selected))
        return Transaction(inputs, tuple(token_output(state, self.parts) for state in outputs)), outputs

    def test_canonical_mixed_subsets(self):
        for positions in (range(64), range(0, 128, 2), sorted(Random(42).sample(range(128), 64))):
            tx, outputs = self.shape(positions)
            witness = wide_witness(tx, self.scope, self.leaves, positions, outputs)
            digest = hash256(preimage_otda(tx, 0, COMPACT_SCRIPTCODE, CHRONICLE_ALL))
            self.assertEqual(evaluate(witness+self.rules), ([b"\x01"], [b"\x61", digest]))
            witness = wide_witness(tx, self.scope, self.leaves, positions, outputs,
                                   compact_outputs=True, verifier_sats=self.verifier_sats)
            digest = hash256(preimage_all(tx, 0, self.verifier_sats, COMPACT_SCRIPTCODE))
            self.assertEqual(evaluate(witness+self.compact), ([b"\x01"], [digest]))

    def test_wrong_vout_copied_slot_successor_lock_and_balances(self):
        selected = tuple(range(0, 128, 2))
        tx, outputs = self.shape(selected)
        wrong_point = replace(tx.inputs[-1], vout=99)
        wrong_lock = replace(tx.outputs[-1], script=tx.outputs[-1].script[:-1]+b"\x00")
        wrong_amounts = [replace(outputs[-1], quantity=outputs[-1].quantity+1),
                         replace(outputs[-1], sats=outputs[-1].sats+1),
                         replace(outputs[-1], frozen=True)]
        cases = [(replace(tx, inputs=(*tx.inputs[:-1], wrong_point)), outputs),
                 (replace(tx, inputs=(*tx.inputs[:-1], tx.inputs[2])), outputs),
                 (replace(tx, outputs=(*tx.outputs[:-1], wrong_lock)), outputs)]
        for state in wrong_amounts:
            cases.append((replace(tx, outputs=(*tx.outputs[:-1], token_output(state, self.parts))),
                          (*outputs[:-1],state)))
        for altered, states in cases:
            for compact, rules in ((False, self.rules), (True, self.compact)):
                witness = wide_witness(altered, self.scope, self.leaves, selected, states,
                                       compact_outputs=compact, verifier_sats=self.verifier_sats)
                with self.assertRaises(ScriptError):
                    evaluate(witness + rules)

    def test_reject_uint64_total_overflow_and_frozen_source(self):
        selected = tuple(range(64))
        for state in (replace(self.leaves[0].state, quantity=2**64-1),
                      replace(self.leaves[0].state, frozen=True)):
            leaves = (replace(self.leaves[0], state=state), *self.leaves[1:])
            tx, outputs = self.shape(selected, leaves)
            if state.frozen:
                outputs = (*outputs[:-1], replace(outputs[-1], frozen=False))
                tx = replace(tx, outputs=tuple(token_output(s, self.parts) for s in outputs))
            for compact in (False, True):
                ruled = wide_rules(self.scope, self.parts, inventory_root(leaves), compact_outputs=compact)
                witness = wide_witness(tx, self.scope, leaves, selected, outputs,
                                       compact_outputs=compact, verifier_sats=self.verifier_sats)
                with self.assertRaises(ScriptError):
                    evaluate(witness+ruled)

    def test_compact_binding_rejects_foreign_context_and_changed_witness_fields(self):
        positions = tuple(range(0, 128, 2))
        tx, states = self.shape(positions)
        legacy = wide_witness(tx, self.scope, self.leaves, positions, states,
                              compact_outputs=True, verifier_sats=self.verifier_sats)
        chronicle = wide_witness(tx, self.scope, self.leaves, positions, states)
        canonical = preimage_all(tx, 0, self.verifier_sats, COMPACT_SCRIPTCODE)
        prevouts = b"".join(item.outpoint() for item in tx.inputs)
        outstates = b"".join(item.encode() for item in states)
        frame = push(outstates) + push(prevouts) + push(canonical)
        self.assertTrue(legacy.endswith(frame))
        underlying = legacy[:-len(frame)]
        altered_states = bytes([outstates[0] ^ 1]) + outstates[1:]
        foreign_vin = preimage_all(tx, 1, self.verifier_sats, COMPACT_SCRIPTCODE)
        for unlock, rules in (
            (legacy, self.rules), (chronicle, self.compact),
            (underlying + push(altered_states) + push(prevouts) + push(canonical), self.compact),
            (underlying + push(outstates) + push(prevouts[:-1]) + push(canonical), self.compact),
            (underlying + push(outstates) + push(prevouts[::-1]) + push(canonical), self.compact),
            (underlying + push(outstates) + push(prevouts) + push(foreign_vin), self.compact),
        ):
            with self.assertRaises(ScriptError):
                evaluate(unlock+rules)

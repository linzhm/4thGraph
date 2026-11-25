import unittest

from conservation_inputs import actual_token_inputs_material, actual_token_inputs_script
from conservation_probe import lock
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from transfer import shared_guard_lock


class ConservationInputTests(unittest.TestCase):
    def setUp(self):
        approved = shared_guard_lock(asm("OP_1"))
        self.companion = Transaction((Input(b"c" * 32, 0),), (Output(2000, approved),))
        self.outputs = tuple(
            Output(1000, lock(TokenState(b"a" * 32, 640 - i, fixture_signer(11 + i)[0]), companion_lock=approved))
            for i in range(2)
        )
        self.parents = tuple(Transaction((Input(bytes([i + 1]) * 32, 0),), (output,))
                             for i, output in enumerate(self.outputs))
        self.code = actual_token_inputs_script()

    def check(self, actual_pairs, supplied_pairs=None, supplied_companion=None):
        prevouts = b"v" * 36 + Input(self.companion.txid_wire(), 0).outpoint() + b"".join(
            Input(parent.txid_wire(), vout).outpoint() for parent, vout in actual_pairs
        )
        witness = actual_token_inputs_material(supplied_pairs or actual_pairs, supplied_companion or self.companion)
        retained = [b"Groth16 fields", b"ordered outputs", prevouts, b"current preimage"]
        argument = push(retained[0]) + witness + b"".join(map(push, retained[1:]))
        self.assertEqual(evaluate(argument + self.code), (retained, []))

    def test_authenticates_separate_and_shared_parent_inputs(self):
        separate = tuple((tx, 0) for tx in self.parents)
        same = Transaction((Input(b"s" * 32, 0),), self.outputs)
        self.check(separate)
        self.check(((same, 0), (same, 1)))
        self.assertLess(len(actual_token_inputs_material(((same, 0), (same, 1)), self.companion)),
                        len(actual_token_inputs_material(separate, self.companion)))

    def test_requires_approved_token_at_each_actual_outpoint(self):
        actual = tuple((tx, 0) for tx in self.parents)
        unapproved = Transaction((Input(b"u" * 32, 1),), (Output(1000, asm("OP_1")),))
        other_companion = Transaction((Input(b"d" * 32, 1),), self.companion.outputs)
        for actual_slots, witnesses, companion in (
            ((actual[0], (unapproved, 0)), None, None),
            (actual, (actual[0], actual[0]), None),
            ((actual[0], (actual[1][0], 1)), None, None),
            (actual, None, other_companion),
        ):
            with self.assertRaises(ScriptError):
                self.check(actual_slots, witnesses, companion)

"""Token-side and companion checks for the shared ordinary verifier layout."""

from dataclasses import replace
from hashlib import sha256
from importlib.util import find_spec
import unittest

from operational_token import (
    FLAG_OFFSET, FORKID_ALL, TokenPolicy, _shared_guard_digest_script, freeze_witness,
    ordinary_witness, shared_guard_witness,
)
from projects.cctp.recursion.continuity_statement import ParentReceipt
from shared.evaluate import evaluate
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_forkid
from test_operational_token import fixture_signer, parent_for
from transaction_relation import TokenState
from transfer import shared_guard_lock


class SharedOrdinaryGuardTemplateTests(unittest.TestCase):
    def test_exact_serialized_guard_does_not_depend_on_universal_script_length(self):
        fragment = _shared_guard_digest_script()
        for script in (b"a", b"b" * 253, b"c" * 70_000):
            actual_digest = sha256(blob(script)).digest()
            expected_companion = sha256(blob(shared_guard_lock(script))).digest()
            self.assertEqual(evaluate(push(actual_digest) + fragment), ([expected_companion], []))


@unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
class SharedOrdinaryGuardCompleteInputs(unittest.TestCase):
    def setUp(self):
        owner, self.sign_owner = fixture_signer(11)
        freeze, self.sign_admin = fixture_signer(12)
        # Valid fixture scripts. Full recursive verification is tested by
        # the wide runner; these isolate the complete token and guard inputs.
        self.verifier_lock = push(bytes(4096)) + asm("OP_DROP OP_1")
        self.policy = TokenPolicy((self.verifier_lock,), freeze, certified_admin=True, shared_ordinary_guard=True)
        self.verifier_parent = parent_for(Output(100_000, self.verifier_lock), 1)
        self.companion = parent_for(Output(100_000, self.policy.shared_guard_lock()), 2)
        self.state = TokenState(b"a" * 32, 640, owner)
        self.first = parent_for(Output(1500, self.policy.lock(self.state)), 3)
        self.second = parent_for(Output(1500, self.policy.lock(replace(self.state, quantity=384))), 4)

    @staticmethod
    def check(tx, parents):
        from shared.chain_gang import validate_at_heights

        validate_at_heights(tx, parents, spend_height=100, activation_height=2,
                            utxo_heights=(3,) * len(parents))

    @staticmethod
    def spend(parent):
        return Input(parent.txid_wire(), 0)

    def shared_tx(self, verifier=None, companion=None, tokens=None):
        tokens = (self.first, self.second) if tokens is None else tokens
        parents = (self.verifier_parent if verifier is None else verifier,
                   self.companion if companion is None else companion, *tokens)
        quantity = sum(self.policy.parse(parent.outputs[0].script).quantity for parent in parents[2:])
        output = Output(1500, self.policy.lock(replace(self.state, quantity=quantity)))
        return Transaction(tuple(map(self.spend, parents)), (output,)), parents

    def raw_companion(self, tx, verifier, companion):
        prevouts = b"".join(item.outpoint() for item in tx.inputs)
        guard = companion.outputs[0]
        preimage = preimage_forkid(tx, 1, guard.value, guard.script, FORKID_ALL)
        return push(verifier.serialize()) + push(prevouts) + push(preimage)

    def raw_token(self, tx, index, token, companion, selector="OP_1"):
        prevouts = b"".join(item.outpoint() for item in tx.inputs)
        output = token.outputs[0]
        preimage = preimage_forkid(tx, index, output.value, output.script, FORKID_ALL)
        return (push(self.sign_owner(hash256(preimage)) + bytes([FORKID_ALL]))
                + push(companion.serialize()) + push(prevouts) + push(preimage)
                + asm(selector + " OP_0"))

    def test_shared_tokens_bind_one_compact_companion(self):
        tx, parents = self.shared_tx()
        signed = tx.with_script(1, shared_guard_witness(tx, self.policy, *parents[:2]))
        self.assertTrue(signed.inputs[1].script.startswith(push(self.verifier_parent.serialize())))
        for index, token in enumerate(parents[2:], start=2):
            witness = ordinary_witness(tx, index, token, self.policy, self.verifier_parent, self.sign_owner,
                                       shared_guard_parent=self.companion)
            self.assertIn(push(self.companion.serialize()), witness)
            self.assertNotIn(push(self.verifier_parent.serialize()), witness)
            signed = signed.with_script(index, witness)
        self.check(signed, parents)
        digest, = self.policy.verifier_hashes()
        self.assertEqual(self.first.outputs[0].script.count(digest), 1)
        self.assertEqual(self.first.outputs[0].script[FLAG_OFFSET], 0)

    def test_direct_ordinary_and_certified_freeze_still_work_for_wide_policy(self):
        direct = Transaction(tuple(map(self.spend, (self.verifier_parent, self.first))), (self.first.outputs[0],))
        witness = ordinary_witness(direct, 1, self.first, self.policy, self.verifier_parent, self.sign_owner)
        self.assertTrue(witness.endswith(asm("OP_0 OP_0")))
        self.check(direct.with_script(1, witness), (self.verifier_parent, self.first))

        frozen = replace(self.state, frozen=True)
        pause = Transaction(tuple(map(self.spend, (self.first, self.verifier_parent))), (
            Output(self.first.outputs[0].value, self.policy.lock(frozen)), ParentReceipt((b"p" * 32,)).output(),
        ))
        witness = freeze_witness(pause, 0, self.first, self.policy, self.sign_admin,
                                 verifier_parent=self.verifier_parent)
        self.check(pause.with_script(0, witness), (self.first, self.verifier_parent))
        self.assertEqual(pause.outputs[0].script[FLAG_OFFSET], 1)

    def test_companion_rejects_actual_wrong_vin_zero_verifier(self):
        wrong_verifier = parent_for(Output(100_000, asm("OP_2")), 5)
        tx, parents = self.shared_tx(verifier=wrong_verifier, tokens=(self.first,))
        with self.assertRaisesRegex(ValueError, "invalid verifier parent"):
            shared_guard_witness(tx, self.policy, wrong_verifier, self.companion)
        witness = self.raw_companion(tx, wrong_verifier, self.companion)
        owner = self.raw_token(tx, 2, self.first, self.companion)
        with self.assertRaises(ValueError):
            self.check(tx.with_script(1, witness).with_script(2, owner), parents)

    def test_token_rejects_valid_companion_for_another_verifier(self):
        other_lock = asm("OP_2")
        other_verifier = parent_for(Output(100_000, other_lock), 5)
        other_companion = parent_for(Output(100_000, shared_guard_lock(other_lock)), 6)
        tx, parents = self.shared_tx(verifier=other_verifier, companion=other_companion, tokens=(self.first,))
        with self.assertRaisesRegex(ValueError, "invalid shared guard"):
            self.policy.selected_shared_guard(tx, other_companion.serialize())
        signed = tx.with_script(1, self.raw_companion(tx, other_verifier, other_companion))
        signed = signed.with_script(2, self.raw_token(tx, 2, self.first, other_companion))
        with self.assertRaises(ValueError):
            self.check(signed, parents)

    def test_rejects_funder_substitution_and_noncanonical_selector(self):
        tx, parents = self.shared_tx(tokens=(self.first,))
        wrong_raw = replace(self.companion, locktime=1)
        with self.assertRaisesRegex(ValueError, "invalid shared guard"):
            ordinary_witness(tx, 2, self.first, self.policy, self.verifier_parent, self.sign_owner,
                             shared_guard_parent=wrong_raw)
        signed = tx.with_script(1, shared_guard_witness(tx, self.policy, *parents[:2]))
        for witness in (
            self.raw_token(tx, 2, self.first, wrong_raw),
            self.raw_token(tx, 2, self.first, self.companion, selector="OP_2"),
        ):
            with self.assertRaises(ValueError):
                self.check(signed.with_script(2, witness), parents)
        with self.assertRaisesRegex(ValueError, "requires certified"):
            TokenPolicy((self.verifier_lock,), self.policy.freeze_key, shared_ordinary_guard=True)

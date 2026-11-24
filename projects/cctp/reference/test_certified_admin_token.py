"""Check the token-side covenant for certified administrative continuity."""

from dataclasses import replace
from hashlib import sha256
from importlib.util import find_spec
import unittest

from operational_token import FLAG_OFFSET, FORKID_ALL, FORKID_SINGLE, TokenPolicy, freeze_witness, ordinary_witness
from projects.cctp.recursion.continuity_statement import ParentReceipt, RECEIPT_PREFIX
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_forkid
from test_operational_token import fixture_signer, parent_for
from transaction_relation import TokenState
import test_operational_token as legacy_fixture


class CertifiedAdminTokenTests(unittest.TestCase):
    def test_legacy_lock_offsets_and_transaction_fixture_are_byte_identical(self):
        legacy = legacy_fixture.OperationalTokenTests()
        legacy.setUp()
        active = legacy.states[0]
        frozen = replace(active, frozen=True)
        for state, expected in (
            (active, "ebbea3544049419e0aa51984cb02917f3ae4dd1d43cdf0e4432729b5378faac8"),
            (frozen, "de9e4d339c64acc2745bce7add04d2a05f766f39d3058de652bc7c8f5aaa7ef9"),
        ):
            lock = legacy.policy.lock(state)
            self.assertEqual(sha256(lock).hexdigest(), expected)
            self.assertEqual(lock[FLAG_OFFSET], int(state.frozen))
        frozen_states = tuple(replace(state, frozen=True) for state in legacy.states)
        signed = legacy.admin_signed(legacy.admin_tx(legacy.parents, frozen_states), legacy.parents)
        self.assertEqual(sha256(signed.serialize()).hexdigest(),
                         "6aa9381f9902097a1cfad52f1ee016e5bb4d27ddebba69bdc92e91a928b0824c")


@unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
class CertifiedAdminCompleteInputs(unittest.TestCase):
    def setUp(self):
        owner, self.sign_owner = fixture_signer(11)
        freeze_key, self.sign_admin = fixture_signer(12)
        # The simple funding lock isolates the token guard. The continuity
        # verifier's separate tests are responsible for the recursive proof.
        self.lock = asm("OP_1")
        self.policy = TokenPolicy((self.lock,), freeze_key, certified_admin=True)
        self.state = TokenState(b"a" * 32, 640, owner)
        self.origin = parent_for(Output(1500, self.policy.lock(self.state)), 1)
        self.verifier = parent_for(Output(10_000, self.lock), 2)
        self.other_verifier = parent_for(Output(10_000, self.lock), 3)
        self.rogue = parent_for(Output(10_000, asm("OP_2")), 4)
        self.receipt = ParentReceipt((b"p" * 32,)).output()

    @staticmethod
    def check(tx, parents):
        from shared.chain_gang import validate_at_heights

        validate_at_heights(tx, parents, spend_height=100, activation_height=2,
                            utxo_heights=(3,) * len(parents))

    def toggle(self, token, verifier, *, outputs=None):
        previous = token.outputs[0]
        state = self.policy.parse(previous.script)
        exact = (Output(previous.value, self.policy.lock(replace(state, frozen=not state.frozen))), self.receipt)
        return Transaction((Input(token.txid_wire(), 0), Input(verifier.txid_wire(), 0)),
                           exact if outputs is None else outputs)

    def force_admin(self, tx, token, verifier, *, index=0, signer=None, receipt=None):
        previous = token.outputs[0]
        full = preimage_forkid(tx, index, previous.value, previous.script, FORKID_ALL)
        paired = preimage_forkid(tx, index, previous.value, previous.script, FORKID_SINGLE)
        signer = self.sign_admin if signer is None else signer
        supplied_receipt = self.receipt.serialize() if receipt is None else receipt.serialize()
        witness = b"".join(push(item) for item in (
            signer(hash256(full)) + bytes([FORKID_ALL]), verifier.serialize(),
            b"".join(txin.outpoint() for txin in tx.inputs), full, supplied_receipt, paired,
        )) + asm("OP_1")
        return tx.with_script(index, witness)

    def test_one_guard_and_fixed_flag_offset_under_both_states(self):
        guard, = self.policy.verifier_hashes()
        for state in (self.state, replace(self.state, frozen=True)):
            lock = self.policy.lock(state)
            self.assertEqual(lock.count(guard), 1)
            self.assertEqual(lock[FLAG_OFFSET], int(state.frozen))
            self.assertEqual(self.policy.parse(lock), state)
        with self.assertRaisesRegex(ValueError, "one exact verifier"):
            TokenPolicy((self.lock, asm("OP_2")), self.policy.freeze_key, certified_admin=True)

    def test_certified_freeze_unfreeze_and_ordinary_spend(self):
        freeze = self.toggle(self.origin, self.verifier)
        freeze = freeze.with_script(0, freeze_witness(freeze, 0, self.origin, self.policy, self.sign_admin,
                                                      verifier_parent=self.verifier))
        self.check(freeze, (self.origin, self.verifier))
        self.assertTrue(self.policy.parse(freeze.outputs[0].script).frozen)

        resume = self.toggle(freeze, self.other_verifier)
        resume = resume.with_script(0, freeze_witness(resume, 0, freeze, self.policy, self.sign_admin,
                                                       verifier_parent=self.other_verifier))
        self.check(resume, (freeze, self.other_verifier))
        self.assertEqual(resume.outputs[0], self.origin.outputs[0])
        self.assertEqual(resume.outputs[1], self.receipt)

        fee = parent_for(Output(10_000, self.lock), 5)
        tx = Transaction((Input(fee.txid_wire(), 0), Input(resume.txid_wire(), 0)), (self.origin.outputs[0],))
        signed = tx.with_script(1, ordinary_witness(tx, 1, resume, self.policy, fee, self.sign_owner))
        self.check(signed, (fee, resume))

        tx = replace(tx, inputs=(tx.inputs[0], Input(freeze.txid_wire(), 0)))
        current = freeze.outputs[0]
        preimage = preimage_forkid(tx, 1, current.value, current.script, FORKID_ALL)
        fields = (self.sign_owner(hash256(preimage)) + bytes([FORKID_ALL]), fee.serialize(),
                  b"".join(txin.outpoint() for txin in tx.inputs), preimage)
        signed = tx.with_script(1, b"".join(push(item) for item in fields) + asm("OP_0"))
        with self.assertRaises(ValueError):
            self.check(signed, (fee, freeze))

    def test_wrong_funding_signer_or_input_index_cannot_toggle(self):
        base = self.toggle(self.origin, self.verifier)
        wrong_parent = self.force_admin(base, self.origin, self.other_verifier)
        rogue = self.force_admin(self.toggle(self.origin, self.rogue), self.origin, self.rogue)
        wrong_signer = self.force_admin(base, self.origin, self.verifier, signer=self.sign_owner)
        reversed_inputs = replace(base, inputs=base.inputs[::-1], outputs=base.outputs[::-1])
        misplaced = self.force_admin(reversed_inputs, self.origin, self.verifier, index=1)
        for tx, parents in (
            (wrong_parent, (self.origin, self.verifier)),
            (rogue, (self.origin, self.rogue)),
            (wrong_signer, (self.origin, self.verifier)),
            (misplaced, (self.verifier, self.origin)),
        ):
            with self.subTest(txid=tx.txid()), self.assertRaises(ValueError):
                self.check(tx, parents)

    def test_malformed_receipt_missing_extra_and_wrong_pair_rejected_by_script(self):
        base = self.toggle(self.origin, self.verifier)
        successor = base.outputs[0]
        bad_owner, _ = fixture_signer(13)
        wrong_amount = replace(successor, script=self.policy.lock(replace(self.state, frozen=True, quantity=641)))
        wrong_holder = replace(successor, script=self.policy.lock(replace(self.state, frozen=True, owner=bad_owner)))
        bad_pad = Output(0, RECEIPT_PREFIX + b"\x01" + b"p" * 32 + bytes(31) + b"\x80")
        variants = (
            ((successor,), None),
            ((successor, self.receipt, Output(1, asm("OP_1"))), None),
            ((successor, ParentReceipt(()).output()), ParentReceipt(()).output()),
            ((successor, ParentReceipt((b"p" * 32, b"q" * 32)).output()), ParentReceipt((b"p" * 32, b"q" * 32)).output()),
            ((successor, bad_pad), bad_pad),
            ((successor, replace(self.receipt, value=1)), replace(self.receipt, value=1)),
            ((successor, self.receipt), ParentReceipt((b"q" * 32,)).output()),
            ((wrong_amount, self.receipt), None),
            ((wrong_holder, self.receipt), None),
            ((replace(successor, value=1499), self.receipt), None),
        )
        for outputs, supplied_receipt in variants:
            tx = replace(base, outputs=outputs)
            signed = self.force_admin(tx, self.origin, self.verifier, receipt=supplied_receipt)
            with self.subTest(txid=tx.txid(), supplied=supplied_receipt), self.assertRaises(ValueError):
                self.check(signed, (self.origin, self.verifier))
        previous = self.origin.outputs[0]
        full = preimage_forkid(base, 0, previous.value, previous.script, FORKID_ALL)
        paired = preimage_forkid(base, 0, previous.value, previous.script, FORKID_SINGLE)
        legacy = push(self.sign_admin(hash256(full)) + bytes([FORKID_ALL])) + push(paired) + asm("OP_1")
        with self.assertRaises(ValueError):
            self.check(base.with_script(0, legacy), (self.origin, self.verifier))

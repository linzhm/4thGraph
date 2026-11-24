"""Opt-in certified mint state covenants, with legacy wire compatibility."""

from dataclasses import replace
from hashlib import sha256
from importlib.util import find_spec
import unittest

from mint import MintPolicy, authorize_mint, authorize_pause, prepare_mint, recover_mint_state
from mint_events import EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy
from projects.cctp.recursion.continuity_statement import ParentReceipt, RECEIPT_PREFIX
from shared.evaluate import ScriptError
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import AssetDescriptor
import test_mint as legacy_fixture


class CertifiedMintTests(unittest.TestCase):
    def setUp(self):
        self.coin_parent = Transaction((Input(b"f" * 32, 0),), (Output(200_000, asm("OP_1")),) * 6)
        self.anchor = self.input_at(self.coin_parent, 0)
        self.asset = AssetDescriptor(1, self.anchor.outpoint(), 6, 7, b"a" * 32, b"p" * 32)
        self.attestor, self.owner, self.freeze = (
            legacy_fixture.public(signer) for signer in (legacy_fixture.ATTESTOR, legacy_fixture.OWNER, legacy_fixture.OTHER)
        )
        # A simple independent vin-one lock isolates state-covenant behavior.
        # The integrated continuity tests supply the actual proof verifier.
        self.verifier_lock = asm("OP_1")
        self.tokens = TokenPolicy((self.verifier_lock,), self.freeze)
        guard, = self.tokens.verifier_hashes()
        self.policy = MintPolicy(self.asset, 84532, b"r" * 20, self.attestor,
                                 self.tokens.lock, certified_verifier_hash=guard)
        self.genesis = self.genesis_for(self.policy)
        self.verifier_parent = self.fund_verifier(1)
        self.deposit = legacy_fixture.event(self.policy, 1, 1024)
        self.receipt = ParentReceipt(())
        self.plan = self.plan_for(self.policy, self.genesis, MintEvents(), self.verifier_parent,
                                  self.deposit, self.receipt)

    @staticmethod
    def input_at(transaction, position=0):
        return Input(transaction.txid_wire(), position)

    def genesis_for(self, policy):
        return Transaction((self.anchor,), (Output(1000, policy.state_lock(EMPTY_ROOT)),))

    def fund_verifier(self, coin_position, lock=None):
        return Transaction((self.input_at(self.coin_parent, coin_position),),
                           (Output(100_000, self.verifier_lock if lock is None else lock),))

    def plan_for(self, policy, prior, events, verifier, deposit, receipt):
        return prepare_mint(policy, prior, events, deposit, self.input_at(verifier),
                            receipt=receipt, verifier_parent=verifier)

    def authorize(self, plan):
        return authorize_mint(plan, lambda _: plan.deposit, legacy_fixture.sign)

    def check_inputs(self, transaction, parents):
        if find_spec("tx_engine"):
            from shared.chain_gang import validate_at_heights

            validate_at_heights(transaction, parents, spend_height=100, activation_height=2,
                                utxo_heights=(3,) * len(parents))

    def force_witness(self, unfinished, *, parent_raw=None, receipt_raw=None, signer=None):
        # Bypass host preflight to exercise the covenant with fresh signatures.
        prior = self.plan.prior.outputs[0]
        preimage = preimage_all(unfinished, 0, prior.value, prior.script)
        signature = legacy_fixture.sign(hash256(preimage), signer or legacy_fixture.ATTESTOR) + b"\x41"
        parent_raw = self.verifier_parent.serialize() if parent_raw is None else parent_raw
        tail = unfinished.outputs[3].serialize() if receipt_raw is None else receipt_raw
        witness = (
            parent_raw, signature, b"".join(self.plan.path), self.deposit.encode(),
            b"".join(i.outpoint() for i in unfinished.inputs), tail, preimage,
        )
        return unfinished.with_script(0, b"".join(push(item) for item in witness))

    def test_legacy_state_script_and_signed_mint_keep_existing_bytes(self):
        fixture = legacy_fixture.MintTests()
        fixture.setUp()
        self.assertEqual(sha256(fixture.policy.state_lock(EMPTY_ROOT)).hexdigest(),
                         "7ac668d224d7a8fdc5a777431899440eba1dd0f297859c8ec5e028f5590242b2")
        signed = self.authorize(fixture.plan())
        self.assertEqual(sha256(signed.serialize()).hexdigest(),
                         "440563e6979bd7032058116b1dff8ba45e59c5c62fd0ea07d02959a69c3dc93b")
        pausable = replace(fixture.policy, pause_authority=self.freeze)
        self.assertEqual(sha256(pausable.state_lock(EMPTY_ROOT)).hexdigest(),
                         "93ad30dfff477e723fc5f2bd7d6dc9c0a7e23abe7b3b223e790f54fa201a0101")
        self.assertEqual(sha256(pausable.state_lock(EMPTY_ROOT, paused=True)).hexdigest(),
                         "246dd7764fab56fad77b1e0fb90dbf499e4c7c2105e65f5a7a366cc686015a7c")

    def test_certified_mints_preserve_state_and_commit_receipt(self):
        first = self.authorize(self.plan)
        self.assertEqual(legacy_fixture.run_script(first, self.genesis), ([b"\x01"], []))
        self.assertEqual(first.outputs[3], self.receipt.output())
        self.assertEqual(first.inputs[1].outpoint(), self.input_at(self.verifier_parent).outpoint())
        self.assertEqual(self.tokens.parse(first.outputs[1].script).quantity, 1024)
        self.check_inputs(self.genesis, (self.coin_parent,))
        self.check_inputs(self.verifier_parent, (self.coin_parent,))
        self.check_inputs(first, (self.genesis, self.verifier_parent))
        verifier = self.fund_verifier(2)
        following = legacy_fixture.event(self.policy, 2, 384)
        plan = self.plan_for(self.policy, first, self.plan.successor, verifier, following, ParentReceipt((b"p" * 32,)))
        second = self.authorize(plan)
        self.assertEqual(legacy_fixture.run_script(second, first), ([b"\x01"], []))
        self.check_inputs(second, (first, verifier))
        restored = recover_mint_state(self.policy, self.genesis, (first, second))
        self.assertEqual(restored.events, plan.successor)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.plan_for(self.policy, second, restored.events, self.fund_verifier(3), self.deposit, self.receipt)

    def test_unapproved_verifier_or_wrong_raw_parent_cannot_authorize(self):
        other = self.fund_verifier(2, asm("OP_2"))
        with self.assertRaisesRegex(ValueError, "script hash"):
            self.plan_for(self.policy, self.genesis, MintEvents(), other, self.deposit, self.receipt)
        tx = replace(self.plan.transaction, inputs=(self.plan.transaction.inputs[0], self.input_at(other)))
        signed = self.force_witness(tx, parent_raw=other.serialize())
        with self.assertRaises(ScriptError):
            legacy_fixture.run_script(signed, self.genesis)
        wrong_parent = self.fund_verifier(3)
        spoof = self.force_witness(self.plan.transaction, parent_raw=wrong_parent.serialize())
        with self.assertRaises(ScriptError):
            legacy_fixture.run_script(spoof, self.genesis)
        with self.assertRaisesRegex(ValueError, "actual verifier funding"):
            authorize_mint(replace(self.plan, verifier_parent=None), lambda _: self.deposit,
                           lambda _: self.fail("unexpected signer call"))

    def test_noncanonical_receipt_and_wrong_attestor_rejected_after_resigning(self):
        tx = self.plan.transaction
        malformed = (
            Output(1, tx.outputs[3].script),
            Output(0, RECEIPT_PREFIX + b"\x03" + bytes(64)),
            Output(0, RECEIPT_PREFIX + b"\x01" + bytes(32) + (b"\0" * 31) + b"\x80"),
            Output(0, tx.outputs[3].script[:-1]),
        )
        for tail in malformed:
            with self.subTest(tail=tail), self.assertRaises(ScriptError):
                broken = replace(tx, outputs=(*tx.outputs[:3], tail))
                legacy_fixture.run_script(self.force_witness(broken), self.genesis)
        with self.assertRaises(ScriptError):
            legacy_fixture.run_script(self.force_witness(tx, signer=legacy_fixture.OTHER), self.genesis)
        with self.assertRaises(ScriptError):
            different_receipt = ParentReceipt((b"w" * 32,)).output().serialize()
            legacy_fixture.run_script(self.force_witness(tx, receipt_raw=different_receipt), self.genesis)
        with self.assertRaisesRegex(ValueError, "continuity receipt"):
            prepare_mint(self.policy, self.genesis, MintEvents(), self.deposit, self.input_at(self.verifier_parent))

    def test_separate_pause_authority_keeps_certified_template(self):
        policy = replace(self.policy, pause_authority=self.freeze)
        genesis = self.genesis_for(policy)
        events = MintEvents()
        admin = lambda digest: legacy_fixture.sign(digest, legacy_fixture.OTHER)
        paused = authorize_pause(policy, genesis, events, self.input_at(self.coin_parent, 4), admin, paused=True)
        self.assertEqual(legacy_fixture.run_script(paused, genesis), ([b"\x01"], []))
        with self.assertRaisesRegex(ValueError, "paused"):
            self.plan_for(policy, paused, events, self.verifier_parent, self.deposit, self.receipt)
        resumed = authorize_pause(policy, paused, events, self.input_at(self.coin_parent, 5), admin, paused=False)
        self.assertEqual(legacy_fixture.run_script(resumed, paused), ([b"\x01"], []))
        mint = self.authorize(self.plan_for(policy, resumed, events, self.verifier_parent, self.deposit, self.receipt))
        self.assertEqual(legacy_fixture.run_script(mint, resumed), ([b"\x01"], []))
        self.check_inputs(paused, (genesis, self.coin_parent))
        self.check_inputs(resumed, (paused, self.coin_parent))
        self.check_inputs(mint, (resumed, self.verifier_parent))

    def test_counted_certified_pause_preserves_nonzero_cumulative_issuance(self):
        lock = asm("OP_DEPTH OP_IF OP_DROP OP_ENDIF OP_1")
        tokens = TokenPolicy((lock,), self.freeze)
        policy = replace(self.policy, lock_token=tokens.lock, certified_verifier_hash=tokens.verifier_hashes()[0],
                         pause_authority=self.freeze, certified_pause=True, state_version=2)
        genesis = self.genesis_for(policy)
        funders = tuple(self.fund_verifier(index, lock) for index in (1, 2, 3))
        plan = self.plan_for(policy, genesis, MintEvents(), funders[0], self.deposit, self.receipt)
        minted = self.authorize(plan)
        self.check_inputs(minted, (genesis, funders[0]))

        admin = lambda digest: legacy_fixture.sign(digest, legacy_fixture.OTHER)
        receipt = ParentReceipt((b"p" * 32,))
        paused = authorize_pause(policy, minted, plan.successor, self.input_at(funders[1]), admin, paused=True,
                                 receipt=receipt, verifier_parent=funders[1])
        resumed = authorize_pause(policy, paused, plan.successor, self.input_at(funders[2]), admin, paused=False,
                                  receipt=receipt, verifier_parent=funders[2])
        self.check_inputs(paused, (minted, funders[1]))
        self.check_inputs(resumed, (paused, funders[2]))
        self.assertEqual(resumed.outputs[0], minted.outputs[0])
        self.assertEqual(recover_mint_state(policy, genesis, (minted, paused, resumed)).cumulative_minted, 1024)

        reset_output = replace(paused.outputs[0], script=policy.state_lock(plan.successor.root, paused=True))
        reset = replace(paused, outputs=(reset_output, paused.outputs[1]))
        previous = minted.outputs[0]
        preimage = preimage_all(reset, 0, previous.value, previous.script)
        fields = (funders[1].serialize(), admin(hash256(preimage)) + b"\x41", b"", b"",
                  b"".join(item.outpoint() for item in reset.inputs), receipt.output().serialize(), preimage)
        reset = reset.with_script(0, b"".join(map(push, fields)) + asm("OP_1"))
        with self.assertRaises(ScriptError):
            legacy_fixture.run_script(reset, minted)

    def test_certified_pause_preserves_root_and_rebuilds_mint_history(self):
        lock = asm("OP_DEPTH OP_IF OP_DROP OP_ENDIF OP_1")
        tokens = TokenPolicy((lock,), self.freeze)
        policy = replace(self.policy, lock_token=tokens.lock, certified_verifier_hash=tokens.verifier_hashes()[0],
                         pause_authority=self.freeze, certified_pause=True)
        genesis = self.genesis_for(policy)
        events = MintEvents()
        admin = lambda digest: legacy_fixture.sign(digest, legacy_fixture.OTHER)
        first_funding, second_funding, mint_funding = (self.fund_verifier(i, lock) for i in (1, 2, 3))
        paused = authorize_pause(policy, genesis, events, self.input_at(first_funding), admin, paused=True,
                                 receipt=ParentReceipt(()), verifier_parent=first_funding)
        self.check_inputs(paused, (genesis, first_funding))
        frozen = recover_mint_state(policy, genesis, (paused,))
        self.assertEqual((frozen.events, frozen.paused), (events, True))
        with self.assertRaisesRegex(ValueError, "paused"):
            self.plan_for(policy, paused, events, mint_funding, self.deposit, ParentReceipt((b"p" * 32,)))
        resumed = authorize_pause(policy, paused, events, self.input_at(second_funding), admin, paused=False,
                                  receipt=ParentReceipt((b"p" * 32,)), verifier_parent=second_funding)
        self.check_inputs(resumed, (paused, second_funding))
        self.assertEqual(resumed.outputs[0], genesis.outputs[0])
        plan = self.plan_for(policy, resumed, events, mint_funding, self.deposit, ParentReceipt((b"q" * 32,)))
        minted = self.authorize(plan)
        self.check_inputs(minted, (resumed, mint_funding))

        # Confirmed verifier witnesses participate in txids but not in replay of unsigned state transitions.
        minted = minted.with_script(1, asm("OP_1"))
        self.check_inputs(minted, (resumed, mint_funding))
        restored = recover_mint_state(policy, genesis, (paused, resumed, minted))
        self.assertEqual((restored.transaction, restored.events, restored.paused), (minted, plan.successor, False))
        with self.assertRaisesRegex(ValueError, "actual verifier"):
            authorize_pause(policy, genesis, events, self.input_at(first_funding), admin, paused=True,
                            receipt=ParentReceipt(()))

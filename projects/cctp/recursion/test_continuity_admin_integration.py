"""Actual certified token transactions across the administration statement boundary."""

from dataclasses import replace
import json
from pathlib import Path
import unittest

from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

from committed_verifier import load_verifying_key
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import FORKID_ALL, FORKID_SINGLE, freeze_witness, ordinary_witness
from shared.evaluate import ScriptError, evaluate
from shared.script import encode_num
from shared.transaction import Input, Output, Transaction, hash256, preimage_all, preimage_forkid
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


class ContinuityAdminIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key, commitment = load_verifying_key(json.loads(
            (Path(__file__).parent / "testdata/bsb22-proof.json").read_text()
        ))
        issuer, owner, freeze = (fixture_signer(i) for i in (13, 11, 12))
        issuer_key, issuer_sign = issuer
        cls.owner_key, owner_sign = owner
        freeze_key, admin_sign = freeze
        cls.owner_sign = staticmethod(owner_sign)
        cls.admin_sign = staticmethod(admin_sign)
        anchor = Input(b"a" * 32, 0)
        asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)
        template = MintPolicy(asset, 84532, b"v" * 20, issuer_key, lambda _: b"")
        cls.verifier = ContinuityVerifier(template, freeze_key, key, commitment, b"k" * 32,
                                         certified_mints=True, certified_admin=True)
        cls.policy = cls.verifier.policy
        cls.mint_policy = cls.verifier.mint_policy
        cls.genesis = Transaction((anchor,), (Output(50_000, cls.mint_policy.state_lock(EMPTY_ROOT)),))
        cls.mint_funding = cls.funding_at(1)
        event = Deposit(DepositPosition(84532, asset.reserve_domain, template.reserve_contract, b"d" * 32, 0),
                        asset.reserve_asset, asset.network, asset.asset_id(), 1024, 0, cls.owner_key)
        plan = prepare_mint(cls.mint_policy, cls.genesis, MintEvents(), event, cls.outpoint(cls.mint_funding),
                            receipt=ParentReceipt(()), verifier_parent=cls.mint_funding)
        cls.mint = authorize_mint(plan, lambda _: event, issuer_sign)
        cls.statement = cls.verifier.statement_script()
        cls.freeze_funding, cls.resume_funding, cls.transfer_funding = (cls.funding_at(i) for i in (2, 3, 4))
        cls.freeze = cls.toggle(cls.mint, 1, cls.mint_funding, cls.freeze_funding)
        cls.resume = cls.toggle(cls.freeze, 0, cls.freeze_funding, cls.resume_funding)

    @classmethod
    def funding_at(cls, tag):
        return Transaction((Input(bytes([tag]) * 32, 0),), (Output(100_000, cls.verifier.lock),))

    @staticmethod
    def outpoint(tx, vout=0):
        return Input(tx.txid_wire(), vout)

    @classmethod
    def toggle(cls, parent, vout, parent_funding, funding):
        previous = parent.outputs[vout]
        state = cls.policy.parse(previous.script)
        successor = replace(previous, script=cls.policy.lock(replace(state, frozen=not state.frozen)))
        # Both mint and administration use the universal verifier at vin1.
        prior_preimage = preimage_all(parent, 1, parent_funding.outputs[0].value, COMPACT_SCRIPTCODE)
        prior_digest = ParentReceipt.parse(parent.outputs[-1]).digest(
            cls.verifier.asset.asset_id(), cls.verifier.key_digest, hash256(prior_preimage),
        )
        receipt = ParentReceipt((prior_digest,))
        tx = Transaction((cls.outpoint(parent, vout), cls.outpoint(funding)), (successor, receipt.output()))
        return tx.with_script(0, freeze_witness(tx, 0, parent, cls.policy, cls.admin_sign,
                                                verifier_parent=funding))

    def check_token_input(self, tx, vin, previous):
        """Evaluate the actual specialized covenant with native signature digests."""
        digests = {mode: hash256(preimage_forkid(tx, vin, previous.value, previous.script, mode))
                   for mode in (FORKID_ALL, FORKID_SINGLE)}

        def checksig(signature, key):
            try:
                digest = digests[signature[-1]]
                public_key = VerifyingKey.from_string(key, curve=SECP256k1)
                return public_key.verify_digest(signature[:-1], digest, sigdecode=sigdecode_der)
            except (BadSignatureError, IndexError, KeyError):
                return False

        result = evaluate(tx.inputs[vin].script + previous.script, checksig=checksig)
        self.assertEqual(result, ([b"\x01"], []))

    def assert_statement(self, tx, funding, parents, supporting, *, mode, index):
        expected_preimage = preimage_all(tx, index, funding.outputs[0].value, COMPACT_SCRIPTCODE)
        expected_context = hash256(expected_preimage)
        expected_receipt = ParentReceipt.parse(tx.outputs[-1])
        signals = expected_receipt.signals(self.verifier.asset.asset_id(), self.verifier.key_digest, expected_context)
        raw = self.verifier.transaction_material(tx, funding, parents, supporting,
                                                 count=mode, verifier_index=index)
        self.assertEqual(evaluate(raw + self.statement), (list(map(encode_num, signals)), [expected_context]))
        return expected_receipt, expected_context

    def test_signed_mint_freeze_unfreeze_then_ordinary_transfer(self):
        self.check_token_input(self.mint, 0, self.genesis.outputs[0])
        self.assertEqual(self.verifier.validate_mint(self.mint, self.mint_funding, self.genesis),
                         self.assert_statement(self.mint, self.mint_funding, (self.genesis,), (), mode=3, index=1))
        for tx, funding, parent, prior_funding, frozen in (
            (self.freeze, self.freeze_funding, self.mint, self.mint_funding, True),
            (self.resume, self.resume_funding, self.freeze, self.freeze_funding, False),
        ):
            self.check_token_input(tx, 0, parent.outputs[tx.inputs[0].vout])
            self.assertEqual(self.verifier.validate_admin(tx, funding, parent, prior_funding),
                             self.assert_statement(tx, funding, (parent,), (prior_funding,), mode=5, index=1))
            state = self.policy.parse(tx.outputs[0].script)
            self.assertEqual((state.frozen, state.quantity, state.owner), (frozen, 1024, self.owner_key))

        token = self.resume.outputs[0]
        self.assertEqual(token, self.mint.outputs[1])
        receipt = ParentReceipt((self.verifier.proof_digest(self.resume, self.resume_funding),))
        outputs = tuple(self.mint_policy.token_output(quantity, self.owner_key) for quantity in (640, 384))
        tx = Transaction(
            (self.outpoint(self.transfer_funding), self.outpoint(self.resume)), (*outputs, receipt.output()),
        )
        tx = tx.with_script(1, ordinary_witness(tx, 1, self.resume, self.policy, self.transfer_funding,
                                               self.owner_sign))
        self.check_token_input(tx, 1, token)
        self.assertEqual(self.verifier.validate(tx, self.transfer_funding, (self.resume,), (self.resume_funding,)),
                         self.assert_statement(tx, self.transfer_funding, (self.resume,), (self.resume_funding,),
                                               mode=1, index=0))

    def test_wrong_prior_funding_or_receipt_rejected(self):
        forged_funder = replace(self.freeze_funding, locktime=1)
        forged_receipt = ParentReceipt((b"x" * 32,)).output()
        reset = replace(self.resume, outputs=(self.resume.outputs[0], forged_receipt))
        for tx, parent, previous_verifier in (
            (self.resume, self.freeze, forged_funder),
            (self.resume, self.mint, self.mint_funding),
            (reset, self.freeze, self.freeze_funding),
        ):
            with self.subTest(txid=tx.txid(), parent=parent.txid(), support=previous_verifier.txid()):
                with self.assertRaises(ValueError):
                    self.verifier.validate_admin(tx, self.resume_funding, parent, previous_verifier)
                material = self.verifier.transaction_material(
                    tx, self.resume_funding, (parent,), (previous_verifier,), count=5, verifier_index=1,
                )
                with self.assertRaises(ScriptError):
                    evaluate(material + self.statement)

import json
from dataclasses import replace
from importlib.util import find_spec
from pathlib import Path
import unittest

from committed_verifier import load_verifying_key
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier
from mint import MintPolicy, authorize_mint, authorize_pause, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, encode_num, number, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


class ContinuityVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key, commitment = load_verifying_key(json.loads(
            (Path(__file__).parent / "testdata/bsb22-proof.json").read_text()
        ))
        issuer, issuer_signer = fixture_signer(13)
        freeze, _ = fixture_signer(12)
        cls.owner, _ = fixture_signer(11)
        anchor = Input(b"a" * 32, 0)
        asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)
        template = MintPolicy(asset, 84532, b"r" * 20, issuer, lambda _: b"")
        cls.verifier = ContinuityVerifier(template, freeze, key, commitment, b"k" * 32)
        mint_policy = cls.verifier.mint_policy
        cls.genesis = Transaction((anchor,), (Output(50_000, mint_policy.state_lock(EMPTY_ROOT)),))
        deposit = Deposit(DepositPosition(84532, 7, mint_policy.reserve_contract, b"d" * 32, 0),
                          asset.reserve_asset, 1, asset.asset_id(), 1024, 0, cls.owner)
        plan = prepare_mint(mint_policy, cls.genesis, MintEvents(), deposit, Input(b"s" * 32, 0))
        cls.minted = authorize_mint(plan, lambda _: deposit, issuer_signer)
        cls.statement = cls.verifier.statement_script()

    def create(self, i, parents, support, input_indices, quantities, *, base=False):
        receipt = ParentReceipt(()) if base else ParentReceipt(tuple(
            self.verifier.proof_digest(parent, funding) for parent, funding in zip(parents, support, strict=True)
        ))
        funder = Transaction((Input(bytes([i]) * 32, 0),), (Output(100_000, self.verifier.lock),))
        inputs = (Input(funder.txid_wire(), 0), *(Input(parent.txid_wire(), index)
                  for parent, index in zip(parents, input_indices, strict=True)))
        outputs = (*(self.verifier.mint_policy.token_output(q, self.owner) for q in quantities), receipt.output())
        return Transaction(inputs, outputs), funder, parents, support

    def run_statement(self, args, count):
        return evaluate(self.verifier.transaction_material(*args, count=count) + self.statement)

    @unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
    def test_optional_zero_padding_only_precedes_ordinary_transfer_branches(self):
        from shared.chain_gang import validate_at_heights

        with self.assertRaisesRegex(ValueError, "certified mint"):
            replace(self.verifier, align_output_count=True)
        base = replace(self.verifier, certified_mints=True)
        aligned = replace(base, align_output_count=True)
        statement = base.statement_script()
        self.assertTrue(aligned.statement_script().endswith(statement))
        prefix = aligned.statement_script()[:-len(statement)]
        # Check the added lock prefix in consensus mode, including its remaining stack.
        for mode, field, valid in (
            (1, b"", True), (2, push(b""), True), (1, push(bytes(255)), True),
            (2, b"\x4c\x01\x00", True), (2, b"\x4d\x01\x00\x00", True),
            (2, b"\x4e\x01\x00\x00\x00\x00", True), (3, b"", True),
            (3, push(bytes(10)), False), (1, push(bytes(256)), False), (2, push(b"\x81"), False),
        ):
            with self.subTest(mode=mode, field_bytes=len(field)):
                lock = prefix + asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY") + number(mode) + asm("OP_EQUAL")
                funding = Transaction((Input(b"f" * 32, 0),), (Output(2, lock),))
                witness = number(mode) + field
                tx = Transaction((Input(funding.txid_wire(), 0, witness),), (Output(1, asm("OP_1")),))
                context = dict(spend_height=10, activation_height=2, utxo_heights=(3,))
                if valid:
                    validate_at_heights(tx, (funding,), **context)
                else:
                    with self.assertRaises((ValueError, RuntimeError)):
                        validate_at_heights(tx, (funding,), **context)

    def test_root_one_recursive_parent_and_independent_or_shared_two(self):
        first = self.create(1, (self.minted,), (self.genesis,), (1,), (640, 384), base=True)
        second = self.create(2, (first[0],), (first[1],), (0,), (500, 140))
        third = self.create(3, (first[0], second[0]), (first[1], second[1]), (1, 0), (700, 184))
        fourth = self.create(4, (third[0], third[0]), (third[1], third[1]), (0, 1), (600, 284))
        for args, count in zip((first, second, third, fourth), (0, 1, 2, 2), strict=True):
            tx, funder, _, _ = args
            receipt, context = self.verifier.validate(*args)
            signals = receipt.signals(self.verifier.asset.asset_id(), self.verifier.key_digest, context)
            auth = hash256(preimage_all(tx, 0, funder.outputs[0].value, COMPACT_SCRIPTCODE))
            self.assertEqual(self.run_statement(args, count), (list(map(encode_num, signals)), [auth]))

    def test_rejects_forged_base_old_fundings_and_changed_receipt(self):
        first = self.create(1, (self.minted,), (self.genesis,), (1,), (640, 384), base=True)
        second = self.create(2, (first[0],), (first[1],), (0,), (500, 140))
        bogus_base = self.create(5, (first[0],), (self.genesis,), (1,), (200, 184), base=True)
        changed_receipt = replace(second[0], outputs=(
            *second[0].outputs[:2], ParentReceipt((b"x" * 32,)).output(),
        ))
        changed_amount = replace(second[0], outputs=(
            self.verifier.mint_policy.token_output(501, self.owner), *second[0].outputs[1:],
        ))
        for args, count in (
            (bogus_base, 0), (second, 0),
            ((*first[:3], (replace(self.genesis, locktime=1),)), 0),
            ((*second[:3], (replace(first[1], locktime=1),)), 1),
            ((changed_receipt, *second[1:]), 1),
            ((changed_amount, *second[1:]), 1),
        ):
            with self.assertRaises(ScriptError):
                self.run_statement(args, count)

    def test_certified_mint_state_and_output_feed_the_same_proof_profile(self):
        verifier = replace(self.verifier, certified_mints=True)
        policy = verifier.mint_policy
        _, issuer_signer = fixture_signer(13)
        genesis = replace(self.genesis, outputs=(Output(50_000, policy.state_lock(EMPTY_ROOT)),))
        statement = verifier.statement_script()

        def fund(index):
            return Transaction((Input(bytes([index]) * 32, 0),), (Output(100_000, verifier.lock),))

        def mint(index, quantity, prior, events, prior_funding=None):
            funding = fund(index)
            ancestors = () if prior_funding is None else (verifier.proof_digest(prior, prior_funding),)
            receipt = ParentReceipt(ancestors)
            deposit = Deposit(DepositPosition(84532, 7, policy.reserve_contract, bytes([index]) * 32, 0),
                              verifier.asset.reserve_asset, 1, verifier.asset.asset_id(), quantity, 0, self.owner)
            plan = prepare_mint(policy, prior, events, deposit, Input(funding.txid_wire(), 0),
                                receipt=receipt, verifier_parent=funding)
            return authorize_mint(plan, lambda _: deposit, issuer_signer), funding, plan.successor

        def check(tx, funding, args, mode, index):
            receipt, context = verifier.context(tx, funding)
            signals = receipt.signals(verifier.asset.asset_id(), verifier.key_digest, context)
            auth = hash256(preimage_all(tx, index, funding.outputs[0].value, COMPACT_SCRIPTCODE))
            material = verifier.transaction_material(tx, funding, *args, count=mode, verifier_index=index)
            self.assertEqual(evaluate(material + statement), (list(map(encode_num, signals)), [auth]))

        first, first_funding, events = mint(1, 1024, genesis, MintEvents())
        second, second_funding, _ = mint(2, 384, first, events, first_funding)
        self.assertFalse(verifier.validate_mint(first, first_funding, genesis)[0].parents)
        self.assertEqual(len(verifier.validate_mint(second, second_funding, first, first_funding)[0].parents), 1)
        check(first, first_funding, ((genesis,), ()), 3, 1)
        check(second, second_funding, ((first,), (first_funding,)), 4, 1)

        carrier = fund(3)
        receipt = ParentReceipt((verifier.proof_digest(first, first_funding),
                                 verifier.proof_digest(second, second_funding)))
        merge = Transaction((Input(carrier.txid_wire(), 0), Input(first.txid_wire(), 1), Input(second.txid_wire(), 1)),
                            (policy.token_output(640, self.owner), policy.token_output(768, self.owner), receipt.output()))
        parents = (first, second)
        support = (first_funding, second_funding)
        self.assertEqual(verifier.validate(merge, carrier, parents, support)[0], receipt)
        check(merge, carrier, (parents, support), 2, 0)

        reset = replace(second, outputs=(*second.outputs[:3], ParentReceipt(()).output()))
        for tx, funding, args, mode in (
            (reset, second_funding, ((first,), ()), 3),
            (second, second_funding, ((first,), (second_funding,)), 4),
        ):
            material = verifier.transaction_material(tx, funding, *args, count=mode, verifier_index=1)
            with self.assertRaises(ScriptError):
                evaluate(material + statement)

    def test_certified_pause_and_resume_can_precede_the_first_mint(self):
        pause_key, pause_sign = fixture_signer(14)
        template = replace(self.verifier.mint_template, pause_authority=pause_key)
        verifier = replace(self.verifier, mint_template=template, certified_mints=True, certified_pause=True)
        policy = verifier.mint_policy
        genesis = replace(self.genesis, outputs=(Output(50_000, policy.state_lock(EMPTY_ROOT)),))
        events = MintEvents()
        statement = verifier.statement_script()

        def fund(index):
            return Transaction((Input(bytes([index]) * 32, 0),), (Output(100_000, verifier.lock),))

        def check(tx, funding, parent, support, receipt, context, mode):
            raw = verifier.transaction_material(tx, funding, (parent,), support, count=mode, verifier_index=1)
            signals = receipt.signals(verifier.asset.asset_id(), verifier.key_digest, context)
            actual = hash256(preimage_all(tx, 1, funding.outputs[0].value, COMPACT_SCRIPTCODE))
            self.assertEqual(evaluate(raw + statement), (list(map(encode_num, signals)), [actual]))

        first, second, third = (fund(i) for i in (1, 2, 3))
        paused = authorize_pause(policy, genesis, events, Input(first.txid_wire(), 0), pause_sign,
                                 paused=True, receipt=ParentReceipt(()), verifier_parent=first)
        receipt, context = verifier.validate_pause(paused, first, genesis)
        check(paused, first, genesis, (), receipt, context, 10)

        resumed = authorize_pause(policy, paused, events, Input(second.txid_wire(), 0), pause_sign, paused=False,
                                  receipt=ParentReceipt((verifier.proof_digest(paused, first),)), verifier_parent=second)
        receipt, context = verifier.validate_pause(resumed, second, paused, first)
        check(resumed, second, paused, (first,), receipt, context, 11)

        _, issuer_signer = fixture_signer(13)
        deposit = Deposit(DepositPosition(84532, 7, policy.reserve_contract, b"d" * 32, 0),
                          verifier.asset.reserve_asset, 1, verifier.asset.asset_id(), 1024, 0, self.owner)
        plan = prepare_mint(policy, resumed, events, deposit, Input(third.txid_wire(), 0),
                            receipt=ParentReceipt((verifier.proof_digest(resumed, second),)), verifier_parent=third)
        minted = authorize_mint(plan, lambda _: deposit, issuer_signer)
        receipt, context = verifier.validate_mint(minted, third, resumed, second)
        check(minted, third, resumed, (second,), receipt, context, 4)

        reset = replace(resumed, outputs=(resumed.outputs[0], ParentReceipt(()).output()))
        with self.assertRaises(ScriptError):
            raw = verifier.transaction_material(reset, second, (paused,), (), count=10, verifier_index=1)
            evaluate(raw + statement)

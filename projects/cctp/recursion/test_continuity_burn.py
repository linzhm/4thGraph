"""Certified burn relation, before the common BSB22 verifier and CHECKSIG."""
from dataclasses import replace
from pathlib import Path
import json
import unittest

from burn_receipt import BurnReceipt
from committed_verifier import load_verifying_key
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier, SINGLE_OUTPUT_MARKER
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from shared.evaluate import ScriptError, evaluate
from shared.script import encode_num
from shared.transaction import Input, Output, Transaction, hash256
from statement import AssetDescriptor
from test_operational_token import fixture_signer


class ContinuityBurnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key, commitment = load_verifying_key(json.loads(
            (Path(__file__).parent / "testdata/bsb22-proof.json").read_text()
        ))
        cls.owner, _ = fixture_signer(11)
        freezer, _ = fixture_signer(12)
        issuer, sign_issuer = fixture_signer(13)
        anchor = Input(b"a" * 32, 0)
        cls.asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)
        template = MintPolicy(cls.asset, 84532, b"r" * 20, issuer, lambda _: b"")
        cls.verifier = ContinuityVerifier(template, freezer, key, commitment, b"k" * 32,
                                         certified_mints=True, certified_admin=True, certified_burns=True,
                                         certified_single_output=True)
        policy = cls.verifier.mint_policy
        genesis = Transaction((anchor,), (Output(50_000, policy.state_lock(EMPTY_ROOT)),))
        events = MintEvents()
        prior = genesis
        prior_funding = None
        origins = []
        for index, amount in ((1, 1024), (2, 384)):
            funding = cls.funding(index)
            preceding = () if prior_funding is None else (cls.verifier.proof_digest(prior, prior_funding),)
            deposit = Deposit(DepositPosition(84532, 7, policy.reserve_contract, bytes([index]) * 32, 0),
                              cls.asset.reserve_asset, 1, cls.asset.asset_id(), amount, 0, cls.owner)
            plan = prepare_mint(policy, prior, events, deposit, Input(funding.txid_wire(), 0),
                                receipt=ParentReceipt(preceding), verifier_parent=funding)
            certified = authorize_mint(plan, lambda _: deposit, sign_issuer)
            origins.append((certified, funding, 1))
            prior, prior_funding, events = certified, funding, plan.successor
        cls.origins = tuple(origins)

    @classmethod
    def funding(cls, index):
        return Transaction((Input(bytes([index]) * 32, 0),), (Output(100_000, cls.verifier.lock),))

    def material(self, origins, outputs, index):
        parents = tuple(item[0] for item in origins)
        supporting = tuple(item[1] for item in origins)
        funding = self.funding(index)
        receipt = ParentReceipt(tuple(self.verifier.proof_digest(p, s) for p, s in zip(parents, supporting, strict=True)))
        tx = Transaction(
            (Input(funding.txid_wire(), 0), *(Input(p.txid_wire(), item[2]) for p, item in zip(parents, origins, strict=True))),
            (*outputs, receipt.output()),
        )
        return tx, funding, parents, supporting

    def burn(self, origins, quantity, *, change=0, fee=0, index=3):
        burn = BurnReceipt(self.asset.asset_id(), self.asset.reserve_domain, b"p" * 20, quantity, fee)
        outputs = (burn.output(),)
        if change:
            outputs += (self.verifier.mint_policy.token_output(change, self.owner),)
        return self.material(origins, outputs, index)

    def test_full_partial_one_two_input_burns_and_continuous_change(self):
        cases = (
            (self.origins[:1], 1024, 0, 6), (self.origins, 1408, 0, 7),
            (self.origins[:1], 640, 384, 8), (self.origins, 640, 768, 9),
        )
        for origins, amount, change, mode in cases:
            with self.subTest(mode=mode):
                args = self.burn(origins, amount, change=change, fee=5)
                receipt, context, burn = self.verifier.validate_burn(*args)
                self.assertEqual((burn.quantity, burn.fee), (amount, 5))
                self.assertEqual(self.verifier.burn_mode(args[0]), mode)
                self.assertEqual(self.verifier.verifier_input_index(args[0]), 0)
                signals = receipt.signals(self.asset.asset_id(), self.verifier.key_digest, context)
                self.assertEqual(evaluate(self.verifier.burn_material(*args) + self.verifier.statement_script()),
                                 (list(map(encode_num, signals)), [context]))
                if change:
                    # A partial burn's only token output can be used with the
                    # same verifier and the exact parent proof context.
                    successor_origin = ((args[0], args[1], 1),)
                    new_outputs = tuple(self.verifier.mint_policy.token_output(q, self.owner)
                                        for q in (change // 2, change - change // 2))
                    successor = self.material(successor_origin, new_outputs, index=4)
                    expected, successor_context = self.verifier.validate(*successor)
                    expected_signals = expected.signals(self.asset.asset_id(), self.verifier.key_digest, successor_context)
                    witness = self.verifier.transaction_material(*successor, count=1)
                    self.assertEqual(evaluate(witness + self.verifier.statement_script()),
                                     (list(map(encode_num, expected_signals)), [successor_context]))

    def test_rejects_malformed_burn_wrong_slots_policy_and_funding(self):
        args = self.burn(self.origins[:1], 640, change=384, fee=5)
        tx, funding, parents, supporting = args
        burn, change, receipt = tx.outputs
        wrong_domain = BurnReceipt(self.asset.asset_id(), 8, b"p" * 20, 640, 5).output()
        bad_quantity = BurnReceipt(self.asset.asset_id(), 7, b"p" * 20, 641, 5).output()
        invalid = (
            replace(tx, outputs=(change, burn, receipt)),
            replace(tx, outputs=(replace(burn, script=burn.script + b"\x00"), change, receipt)),
            replace(tx, outputs=(replace(burn, script=burn.script[:-8] + (640).to_bytes(8, "little")), change, receipt)),
            replace(tx, outputs=(replace(burn, value=1), change, receipt)),
            replace(tx, outputs=(wrong_domain, change, receipt)),
            replace(tx, outputs=(bad_quantity, change, receipt)),
            replace(tx, outputs=(burn, change, ParentReceipt((b"z" * 32,)).output())),
        )
        for bad in invalid:
            with self.subTest(txid=bad.txid()), self.assertRaises(ScriptError):
                witness = self.verifier.transaction_material(bad, funding, parents, supporting, count=8)
                evaluate(witness + self.verifier.statement_script())
        for parent_funding, mode in ((replace(supporting[0], locktime=1), 8), (supporting[0], 9), (supporting[0], 5)):
            witness = self.verifier.transaction_material(tx, funding, parents, (parent_funding,), count=mode)
            with self.assertRaises(ScriptError):
                evaluate(witness + self.verifier.statement_script())

        # A different valid redemption recipient changes the proof statement.
        recipient = BurnReceipt(self.asset.asset_id(), 7, b"q" * 20, 640, 5).output()
        replacement = replace(tx, outputs=(recipient, change, receipt))
        self.assertNotEqual(self.verifier.proof_digest(tx, funding), self.verifier.proof_digest(replacement, funding))

    def test_rejects_duplicate_token_outpoint_and_frozen_parent(self):
        args = self.burn(self.origins[:1] * 2, 2048)
        with self.assertRaisesRegex(ValueError, "duplicated input"):
            self.verifier.validate_burn(*args)
        witness = self.verifier.transaction_material(*args, count=7)
        with self.assertRaises(ScriptError):
            evaluate(witness + self.verifier.statement_script())

        parent, funding, index = self.origins[0]
        active = parent.outputs[index]
        state = self.verifier.policy.parse(active.script)
        frozen = replace(active, script=self.verifier.policy.lock(replace(state, frozen=True)))
        parent = replace(parent, outputs=(parent.outputs[0], frozen, *parent.outputs[2:]))
        args = self.burn(((parent, funding, index),), 1024)
        with self.assertRaises(ValueError):
            self.verifier.validate_burn(*args)
        with self.assertRaises(ScriptError):
            evaluate(self.verifier.transaction_material(*args, count=6) + self.verifier.statement_script())

        full = self.burn(self.origins[:1], 1024, index=11)
        for unspendable in (0, 1):
            args = self.burn(((full[0], full[1], unspendable),), 1024, index=12)
            with self.assertRaises(ValueError):
                self.verifier.validate_burn(*args)
            witness = self.verifier.transaction_material(*args, count=6)
            with self.assertRaises(ScriptError):
                evaluate(witness + self.verifier.statement_script())

    def test_split_merge_and_burn_under_one_verifier(self):
        def token(quantity):
            return self.verifier.mint_policy.token_output(quantity, self.owner)

        single = self.material(self.origins[:1], (token(1024), SINGLE_OUTPUT_MARKER), index=6)
        split = self.material(((single[0], single[1], 0),), (token(640), token(384)), index=7)
        origins = tuple((split[0], split[1], index) for index in (0, 1))
        merge = self.material(origins, (token(1024), SINGLE_OUTPUT_MARKER), index=8)
        for args, mode in ((single, 12), (split, 1), (merge, 13)):
            receipt, context = self.verifier.validate(*args)
            self.assertEqual(self.verifier.transfer_mode(args[0]), mode)
            signals = receipt.signals(self.asset.asset_id(), self.verifier.key_digest, context)
            witness = self.verifier.transaction_material(*args, count=mode)
            self.assertEqual(evaluate(witness + self.verifier.statement_script()),
                             (list(map(encode_num, signals)), [context]))
        burn = self.burn(((merge[0], merge[1], 0),), 640, change=384, index=9)
        receipt, context, _ = self.verifier.validate_burn(*burn)
        signals = receipt.signals(self.asset.asset_id(), self.verifier.key_digest, context)
        self.assertEqual(evaluate(self.verifier.burn_material(*burn) + self.verifier.statement_script()),
                         (list(map(encode_num, signals)), [context]))

        bad_marker = replace(merge[0], outputs=(
            merge[0].outputs[0], replace(SINGLE_OUTPUT_MARKER, value=1), merge[0].outputs[-1],
        ))
        duplicate = self.material(origins[:1] * 2, (token(1280), SINGLE_OUTPUT_MARKER), index=10)
        for args in ((bad_marker, *merge[1:]), duplicate):
            with self.assertRaises(ValueError):
                self.verifier.validate(*args)
            with self.assertRaises(ScriptError):
                evaluate(self.verifier.transaction_material(*args, count=13) + self.verifier.statement_script())

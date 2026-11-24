"""Compare actual wide verifier statements with independently computed ForkID limbs."""
from dataclasses import replace
import json
from pathlib import Path
import unittest

from capacity_verifier import CapacityVerifier
from capacity_tree import capacity_receipt
from capacity_wire import CapacityReceipt, capacity_parent_digest_script, parent_outputs_script
from committed_verifier import load_verifying_key
from continuity_statement import ParentReceipt
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from shared.evaluate import ScriptError, evaluate
from shared.script import encode_num, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


class CapacityVerifierTests(unittest.TestCase):
    compressed_ancestry = False

    @classmethod
    def setUpClass(cls):
        raw = json.loads((Path(__file__).parent / "testdata/bsb22-proof.json").read_text())
        key, commitment = load_verifying_key(raw)
        owner, _ = fixture_signer(11)
        freeze, _ = fixture_signer(12)
        issuer, issuer_sign = fixture_signer(13)
        anchor = Input(b"a" * 32, 0)
        asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)
        template = MintPolicy(asset, 84532, b"v" * 20, issuer, lambda _: b"")
        cls.verifier = CapacityVerifier(template, freeze, key, commitment, b"k" * 32,
                                        certified_mints=True, certified_admin=True, shared_ordinary_guard=True,
                                        compressed_ancestry=cls.compressed_ancestry)
        cls.owner = owner
        cls.policy = cls.verifier.mint_policy
        cls.genesis = Transaction((anchor,), (Output(50_000, cls.policy.state_lock(EMPTY_ROOT)),))
        cls.mint_funder = cls.funding(1, cls.verifier.lock)
        event = Deposit(DepositPosition(84532, 7, cls.policy.reserve_contract, b"d" * 32, 0),
                        asset.reserve_asset, 1, asset.asset_id(), 1024, 0, owner)
        plan = prepare_mint(cls.policy, cls.genesis, MintEvents(), event, Input(cls.mint_funder.txid_wire(), 0),
                            receipt=ParentReceipt(()), verifier_parent=cls.mint_funder)
        cls.mint = authorize_mint(plan, lambda _: event, issuer_sign)

    @staticmethod
    def funding(tag, lock):
        return Transaction((Input(bytes([tag]) * 32, 0),), (Output(90_000_000, lock),))

    def transfer(self, mode, parent, support, positions, quantities, tag):
        funder = self.funding(tag, self.verifier.lock)
        companion = self.funding(tag + 1, self.verifier.policy.shared_guard_lock())
        origins = tuple(Input(parent.txid_wire(), position) for position in positions)
        outputs = tuple(self.policy.token_output(quantity, self.owner) for quantity in quantities)
        receipt = ParentReceipt((self.verifier.proof_digest(parent, support),))
        tx = self.verifier.prepare_capacity(mode, origins, outputs, funder, companion, receipt)
        return tx, funder, companion, ((support, parent),)

    def assert_statement(self, args, *, dictionary_parent=b""):
        receipt, context = self.verifier.validate_capacity(*args)
        want = receipt.signals(self.verifier.asset.asset_id(), self.verifier.key_digest, context)
        tx, funder, _, _ = args
        auth = hash256(preimage_all(tx, 0, funder.outputs[0].value, COMPACT_SCRIPTCODE))
        script = self.verifier.capacity_material(*args, dictionary_parent=dictionary_parent) + self.verifier.statement_script()
        self.assertEqual(evaluate(script), (list(map(encode_num, want)), [auth]))

    def test_fanout_and_single_parent_64_payment(self):
        fanout = self.transfer(17, self.mint, self.mint_funder, (1,), (16,) * 64, 2)
        pay = self.transfer(18, *fanout[:2], range(64), (15, 17) * 32, 4)
        self.assert_statement(fanout)
        self.assert_statement(pay)
        funded_shape = self.verifier._token_script_size
        parent_parser = parent_outputs_script(self.verifier.capacity_modes, funded_shape)
        parent = fanout[0]
        expected = [encode_num(len(parent.outputs)), b"".join(output.serialize() for output in parent.outputs)]
        self.assertEqual(evaluate(push(parent.serialize()) + parent_parser), (expected, []))

    def test_parent_digest_matches_actual_compact_preimage_and_guards(self):
        tx, funding, *_ = self.transfer(16, self.mint, self.mint_funder, (1,), (1024,), 6)
        asset, digest = self.verifier.asset.asset_id(), self.verifier.key_digest
        script = capacity_parent_digest_script(self.verifier.capacity_modes, self.verifier._token_script_size, asset, digest)
        guard = self.verifier.policy.verifier_hashes()[0]
        expected = self.verifier.proof_digest(tx, funding)
        raw = push(tx.serialize()) + push(funding.serialize()) + push(guard)
        self.assertEqual(evaluate(raw + script), ([expected], []))
        other = replace(funding, locktime=1)
        with self.assertRaises(ScriptError):
            evaluate(push(tx.serialize()) + push(other.serialize()) + push(guard) + script)

    def test_capacity_receipt_binds_real_context_and_companion(self):
        tx, funding, companion, pairs = self.transfer(16, self.mint, self.mint_funder, (1,), (1024,), 8)
        receipt = CapacityReceipt.parse(tx.outputs[-1])
        stale = replace(tx, locktime=1)
        substituted = replace(companion, locktime=1)
        for proposed, relay in ((stale, companion), (tx, substituted)):
            with self.assertRaises(ValueError):
                self.verifier.validate_capacity(proposed, funding, relay, pairs)
            with self.assertRaises(ScriptError):
                script = self.verifier.capacity_material(proposed, funding, relay, pairs) + self.verifier.statement_script()
                evaluate(script)
        self.assertEqual(receipt.mode, 16)

    def test_one_payment_aggregates_distinct_actual_parent_statements(self):
        first, first_support, *_ = self.transfer(17, self.mint, self.mint_funder, (1,), (16,) * 64, 10)
        second, second_support, *_ = self.transfer(16, first, first_support, (0,), (16,), 12)
        groups = ((first_support, first), (second_support, second))
        pairs = tuple(sorted(groups, key=lambda pair: int.from_bytes(pair[1].txid_wire(), "little")))
        inputs = tuple(Input(parent.txid_wire(), vout) for _, parent in pairs
                       for vout in (range(1, 64) if parent == first else (0,)))
        roots = capacity_receipt(self.verifier.asset.asset_id(), self.verifier.key_digest, 64,
                                 tuple(self.verifier.proof_digest(parent, support) for support, parent in pairs))
        funding = self.funding(14, self.verifier.lock)
        companion = self.funding(15, self.verifier.policy.shared_guard_lock())
        outputs = tuple(self.policy.token_output(16, self.owner) for _ in range(64))
        tx = self.verifier.prepare_capacity(18, inputs, outputs, funding, companion, roots)
        dictionary = first.serialize() if self.compressed_ancestry else b""
        self.assert_statement((tx, funding, companion, pairs), dictionary_parent=dictionary)
        reversed_roots = ParentReceipt(roots.parents[::-1])
        reordered = self.verifier.prepare_capacity(18, inputs, outputs, funding, companion, reversed_roots)
        with self.assertRaises(ScriptError):
            evaluate(self.verifier.capacity_material(reordered, funding, companion, pairs, dictionary_parent=dictionary)
                     + self.verifier.statement_script())


class CompressedCapacityVerifierTests(CapacityVerifierTests):
    compressed_ancestry = True

"""Test lineage classification separately from the node's consensus validation."""

from dataclasses import replace
import unittest

from burn_receipt import BurnReceipt
from confirmed_lineage import ConfirmedLineage
from fixtures import fixture
from mimo_verifier import MimoProfile
from mint import MintPolicy, authorize_mint, prepare_mint
from mint_events import EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy, freeze_witness
from shared.script import asm
from shared.transaction import Input, Output, Transaction
from statement import AssetDescriptor
from test_mint import ATTESTOR, OTHER, OWNER, event, public, sign
from transaction_relation import TokenState


class ConfirmedLineageTests(unittest.TestCase):
    def setUp(self):
        self.confirmed = {}
        self.lookups = {}
        self.funding = self.confirm(Transaction(
            (Input(bytes(32), 0xffffffff, b"\x01\x03"),),
            (Output(200_000, asm("OP_1")),) * 10,
        ))
        self.anchor = self.spend(self.funding, 0)
        self.asset = AssetDescriptor(1, self.anchor.outpoint(), 6, 7, b"a" * 32, b"p" * 32)
        key, _, _ = fixture()
        self.split, self.merge, self.redeem = tuple(
            MimoProfile(incoming, outgoing, 3, public(OTHER), burn=burn)
            for incoming, outgoing, burn in ((1, 2, False), (2, 1, False), (1, 1, True))
        )
        self.profiles = tuple((p, key) for p in (self.split, self.merge, self.redeem))
        self.locks = tuple(p.lock(self.asset, key) for p, key in self.profiles)
        self.policy = TokenPolicy(self.locks, public(OTHER))
        self.mint_policy = MintPolicy(self.asset, 84532, b"r" * 20, public(ATTESTOR), self.policy.lock)
        self.verifiers = tuple(
            self.confirm(Transaction((self.spend(self.funding, i + 1),), (Output(1000, lock),)))
            for i, lock in enumerate(self.locks)
        )
        self.genesis = self.confirm(Transaction((self.anchor,), (Output(1500, self.mint_policy.state_lock(EMPTY_ROOT)),)))
        deposit = event(self.mint_policy, 1, 1024)
        self.base = prepare_mint(self.mint_policy, self.genesis, MintEvents(), deposit, self.spend(self.funding, 4))
        self.minted = self.confirm(authorize_mint(self.base, lambda _: deposit, sign))
        self.lineage = ConfirmedLineage(self.mint_policy, self.policy, self.profiles, self.load)

    def load(self, txid):
        self.lookups[txid] = self.lookups.get(txid, 0) + 1
        return self.confirmed.get(txid)

    def confirm(self, tx):
        self.confirmed[tx.txid_wire()] = tx.serialize()
        return tx

    def token(self, quantity, *, owner=OWNER, frozen=False):
        state = TokenState(self.asset.asset_id(), quantity, public(owner), frozen)
        return Output(1000, self.policy.lock(state))

    @staticmethod
    def spend(tx, vout=0):
        return Input(tx.txid_wire(), vout)

    def ordinary(self, verifier_index, spends, outputs):
        # The mock loader represents an already consensus-validated chain.
        # The integration runner supplies real Groth16 and BSV signatures.
        return self.confirm(Transaction((self.spend(self.verifiers[verifier_index]), *spends), outputs))

    def admin(self, parent, vout, quantity, frozen):
        tx = Transaction((self.spend(parent, vout),), (self.token(quantity, frozen=frozen),))
        witness = freeze_witness(tx, 0, parent, self.policy, lambda digest: sign(digest, OTHER))
        return self.confirm(tx.with_script(0, witness))

    def test_exact_wallet_and_burn_vouts_across_mint_split_freeze_merge(self):
        self.assertTrue(self.lineage.valid_creation(self.minted, 1))
        self.assertFalse(self.lineage.valid_creation(self.minted, 0))
        split = self.ordinary(0, (self.spend(self.minted, 1),), (self.token(640), self.token(384)))
        frozen = self.admin(split, 0, 640, True)
        self.assertTrue(self.lineage.token(frozen.txid_wire(), 0).frozen)
        active = self.admin(frozen, 0, 640, False)
        merge = self.ordinary(1, (self.spend(active), self.spend(split, 1)), (self.token(1024),))
        receipt = BurnReceipt(self.asset.asset_id(), self.asset.reserve_domain, b"b" * 20, 640)
        burn = self.ordinary(2, (self.spend(merge),), (self.token(384), receipt.output()))
        self.lookups.clear()
        self.assertEqual(self.lineage.burn(burn.txid_wire(), 1), receipt)
        self.assertEqual(self.lookups[split.txid_wire()], 1)
        self.assertEqual(self.lineage.token(burn.txid_wire(), 0).quantity, 384)
        with self.assertRaisesRegex(ValueError, "authenticated burn receipt"):
            self.lineage.burn(burn.txid_wire(), 0)
        with self.assertRaisesRegex(ValueError, "authenticated token output"):
            self.lineage.token(burn.txid_wire(), 1)

    def test_independent_mint_parent_and_reorg(self):
        deposit = event(self.mint_policy, 2, 384)
        second = prepare_mint(self.mint_policy, self.minted, self.base.successor, deposit, self.spend(self.funding, 5))
        second_tx = self.confirm(authorize_mint(second, lambda _: deposit, sign))
        merge = self.ordinary(1, (self.spend(second_tx, 1), self.spend(self.minted, 1)), (self.token(1408),))
        self.assertEqual(self.lineage.token(merge.txid_wire(), 0).quantity, 1408)
        self.confirmed.pop(self.minted.txid_wire())
        with self.assertRaisesRegex(ValueError, "confirmed adopted chain"):
            self.lineage.token(merge.txid_wire(), 0)
        self.assertFalse(self.lineage.valid_creation(merge, 0))

    def test_copied_locks_and_fake_burn_ancestry_are_rejected(self):
        fake = self.confirm(Transaction((self.spend(self.funding, 6),), (self.token(1024),)))
        self.assertFalse(self.lineage.valid_creation(fake, 0))
        descendant = self.ordinary(0, (self.spend(fake),), (self.token(640), self.token(384)))
        self.assertFalse(self.lineage.valid_creation(descendant, 0))

        receipt = BurnReceipt(self.asset.asset_id(), self.asset.reserve_domain, b"b" * 20, 640)
        fake_burn = self.ordinary(2, (self.spend(fake),), (self.token(384), receipt.output()))
        with self.assertRaisesRegex(ValueError, "not linked"):
            self.lineage.burn(fake_burn.txid_wire(), 1)
        counterfeit_mint = self.confirm(replace(self.genesis, inputs=(self.spend(self.funding, 7),)))
        cloned = replace(self.minted, inputs=(self.spend(counterfeit_mint), self.spend(self.funding, 8)))
        self.assertFalse(self.lineage.valid_creation(self.confirm(cloned), 1))

    def test_wrong_lock_profile_and_administrative_vout(self):
        with self.assertRaisesRegex(ValueError, "approved token policy"):
            replace(self.lineage, profiles=self.profiles[:-1])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            replace(self.lineage, profiles=(*self.profiles, self.profiles[0]))
        mismatched = self.ordinary(0, (self.spend(self.minted, 1),), (self.token(1024),))
        self.assertFalse(self.lineage.valid_creation(mismatched, 0))

        invalid = Transaction((self.spend(self.funding, 6), self.spend(self.minted, 1)),
                              (self.token(1024, frozen=True), Output(1000, asm("OP_1"))))
        self.assertFalse(self.lineage.valid_creation(self.confirm(invalid), 0))
        invalid_owner = Transaction((self.spend(self.minted, 1),), (self.token(1024, owner=OTHER, frozen=True),))
        self.assertFalse(self.lineage.valid_creation(self.confirm(invalid_owner), 0))

    def test_loader_cannot_replace_confirmed_transaction_bytes(self):
        self.confirmed[self.minted.txid_wire()] = self.genesis.serialize()
        with self.assertRaisesRegex(ValueError, "requested ID"):
            self.lineage.token(self.minted.txid_wire(), 1)

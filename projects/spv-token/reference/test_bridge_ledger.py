from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from bridge_ledger import BridgeLedger, ChainReference
from burn_receipt import BurnReceipt
from mint_events import Deposit, DepositPosition
from statement import AssetDescriptor
from test_mint import OWNER, public


class BridgeLedgerTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "bridge.sqlite3"
        self.asset = AssetDescriptor(1, b"a" * 36, 6, 7, b"u" * 32, b"p" * 32)
        self.reserve = b"r" * 20
        self.ledger = self.open()
        self.owner = public(OWNER)
        self.recipient = b"d" * 20

    def open(self):
        return BridgeLedger(self.path, self.asset, 84532, self.reserve)

    @staticmethod
    def ref(index, *, block=1, position=1):
        return ChainReference(index.to_bytes(32, "little"), position, block.to_bytes(32, "little"), 100 + block)

    def state_outpoint(self, index=100):
        return self.ref(index, position=0).txid + bytes(4)

    def deposit(self, index=1, *, gross=1024, fee=0, block=1):
        ref = self.ref(index, block=block)
        pos = DepositPosition(84532, 7, self.reserve, ref.txid, ref.position)
        return Deposit(pos, self.asset.reserve_asset, self.asset.network, self.asset.asset_id(),
                       gross, fee, self.owner), ref

    def burn(self, quantity=640, fee=0):
        return BurnReceipt(self.asset.asset_id(), self.asset.reserve_domain, self.recipient, quantity, fee)

    def test_fee_refund_freeze_and_final_balances(self):
        deposit, ref = self.deposit(gross=1029, fee=5)
        event = self.ledger.observe_deposit(deposit, ref, finalized=False)
        self.assertEqual(self.ledger.state(event).phase, "observed")
        with self.assertRaisesRegex(ValueError, "not finalized"):
            self.ledger.authorize_mint(event, b"a" * 32, self.state_outpoint())
        self.ledger.observe_deposit(deposit, ref, finalized=True)
        before = self.ledger.reconcile(source_balance=1029, live_supply=0, frozen_supply=0)
        self.assertEqual(before.totals.pending_mint, 1024)
        self.assertTrue(before.may_authorize)

        self.assertTrue(self.ledger.authorize_mint(event, b"a" * 32, self.state_outpoint()))
        self.ledger.observe_mint(event, self.ref(2), 1024, self.owner, finalized=True)
        frozen = self.ledger.reconcile(source_balance=1029, live_supply=1024, frozen_supply=640)
        self.assertEqual((frozen.live_supply, frozen.frozen_supply), (1024, 640))
        burn = self.ledger.observe_burn(self.burn(fee=7), self.ref(3), finalized=True)
        through_burn = self.ledger.reconcile(source_balance=1029, live_supply=384, frozen_supply=0)
        self.assertEqual(through_burn.totals.pending_release, 640)
        self.assertTrue(through_burn.may_authorize)
        self.ledger.observe_release(burn, self.ref(4), 640, 7, self.recipient, finalized=True)
        self.ledger.observe_reserve_entry(self.ref(5), "fee_sweep", 5)
        self.ledger.observe_reserve_entry(self.ref(6), "provision", 12)
        refund, refund_ref = self.deposit(index=7, gross=10)
        refunded = self.ledger.observe_deposit(refund, refund_ref, finalized=True)
        self.ledger.observe_refund(refunded, self.ref(8), 10)
        self.ledger.observe_reserve_entry(self.ref(9), "return_provision", 12)
        final = self.ledger.reconcile(source_balance=384, live_supply=384, frozen_supply=0)
        self.assertTrue(final.balanced)
        self.assertEqual((final.totals.pending_mint, final.totals.pending_release), (0, 0))
        self.assertEqual((final.totals.released, final.totals.release_fees_paid, final.totals.refunded), (640, 7, 10))
        self.assertEqual(final.totals.mint_fees_retained, 0)
        self.assertEqual(self.ledger.state(refunded).phase, "refunded")

    def test_out_of_order_restart_replay_and_concurrent_authorization(self):
        deposit, ref = self.deposit()
        event = deposit.position.event_id()
        self.ledger.observe_mint(event, self.ref(2), 1024, self.owner, finalized=True)
        self.assertEqual(self.ledger.state(event).phase, "waiting_for_origin")
        restarted = self.open()
        restarted.observe_deposit(deposit, ref, finalized=False)
        restarted.observe_deposit(deposit, ref, finalized=True)
        restarted.observe_deposit(deposit, ref, finalized=False)
        restarted.observe_mint(event, self.ref(2), 1024, self.owner, finalized=True)
        self.assertEqual(restarted.state(event).phase, "settled")
        self.assertEqual(restarted.totals().minted, 1024)

        second, second_ref = self.deposit(3, gross=128)
        second_event = restarted.observe_deposit(second, second_ref, finalized=True)
        digest = bytes(range(32))
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = tuple(pool.map(lambda _: self.open().authorize_mint(second_event, digest, self.state_outpoint(101)), range(12)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(restarted.state(second_event).authorization, digest)
        with self.assertRaisesRegex(ValueError, "different authorization"):
            restarted.authorize_mint(second_event, b"x" * 32, self.state_outpoint(101))
        with self.assertRaisesRegex(ValueError, "different bridge asset"):
            BridgeLedger(self.path, replace(self.asset, network=2), 84532, self.reserve)

    def test_legacy_unscoped_intent_must_be_replayed_before_new_work(self):
        first, first_ref = self.deposit()
        second, second_ref = self.deposit(2)
        legacy = self.ledger.observe_deposit(first, first_ref, finalized=True)
        waiting = self.ledger.observe_deposit(second, second_ref, finalized=True)
        signed_digest = b"a" * 32
        # Model the previous schema's recorded signing intent, which did not
        # have a record of the state outpoint used to compute the digest.
        with sqlite3.connect(self.path) as old:
            old.execute("UPDATE bridge_events SET authorization = ? WHERE event_id = ?", (signed_digest, legacy))
        migrated = self.open()
        with self.assertRaisesRegex(ValueError, "legacy mint authorization"):
            migrated.authorize_mint(waiting, b"b" * 32, self.state_outpoint())
        with self.assertRaisesRegex(ValueError, "different authorization"):
            migrated.authorize_mint(legacy, b"x" * 32, self.state_outpoint())
        self.assertFalse(migrated.authorize_mint(legacy, signed_digest, self.state_outpoint()))
        with self.assertRaisesRegex(ValueError, "another mint already reserved"):
            migrated.authorize_mint(waiting, b"b" * 32, self.state_outpoint())

    def test_confirmed_mint_conflicting_with_reservation_creates_hold(self):
        first, first_ref = self.deposit()
        second, second_ref = self.deposit(2)
        original = self.ledger.observe_deposit(first, first_ref, finalized=True)
        other = self.ledger.observe_deposit(second, second_ref, finalized=True)
        state = self.state_outpoint()
        self.ledger.authorize_mint(original, b"a" * 32, state)
        self.ledger.note_confirmed_mint_spend(state, other, b"b" * 32)
        self.ledger.observe_mint(other, self.ref(3), 1024, self.owner, finalized=True)
        restarted = self.open()
        self.assertEqual(restarted.state(original).phase, "held")
        self.assertEqual(restarted.state(other).phase, "settled")
        with self.assertRaisesRegex(ValueError, "held for review"):
            restarted.authorize_mint(original, b"a" * 32, state)

    def test_preaction_reorg_and_stale_evidence_do_not_reauthorize(self):
        deposit, old = self.deposit()
        event = self.ledger.observe_deposit(deposit, old, finalized=True)
        self.assertTrue(self.ledger.reorg_origin(event, old))
        self.assertFalse(self.ledger.reorg_origin(event, old))
        self.assertEqual(self.ledger.state(event).phase, "orphaned")
        self.assertEqual(self.ledger.totals().pending_mint, 0)
        self.ledger.observe_deposit(deposit, old, finalized=True)
        self.assertEqual(self.ledger.state(event).phase, "orphaned")
        next_ref = replace(old, block_hash=b"b" * 32, height=110)
        self.ledger.observe_deposit(deposit, next_ref, finalized=True)
        self.assertTrue(self.ledger.authorize_mint(event, b"a" * 32, self.state_outpoint()))
        self.ledger.observe_mint(event, self.ref(2), 1024, self.owner, finalized=False)
        self.assertTrue(self.ledger.reorg_effect(event, self.ref(2)))
        self.assertEqual(self.ledger.state(event).phase, "authorized")
        self.assertFalse(self.ledger.authorize_mint(event, b"a" * 32, self.state_outpoint()))

    def test_deep_reorg_and_mismatch_are_durable_holds(self):
        deposit, ref = self.deposit()
        event = self.ledger.observe_deposit(deposit, ref, finalized=True)
        self.ledger.authorize_mint(event, b"a" * 32, self.state_outpoint())
        self.ledger.observe_mint(event, self.ref(2), 1024, self.owner, finalized=True)
        self.assertTrue(self.ledger.reorg_origin(event, ref))
        restarted = self.open()
        self.assertEqual(restarted.state(event).phase, "held")
        report = restarted.reconcile(source_balance=0, live_supply=1024, frozen_supply=0)
        self.assertFalse(report.may_authorize)
        self.assertEqual(report.backing_difference, -1024)
        self.assertEqual(report.totals.unresolved_effects, 1)
        second, second_ref = self.deposit(3)
        other = restarted.observe_deposit(second, second_ref, finalized=True)
        with self.assertRaisesRegex(ValueError, "held for review"):
            restarted.authorize_mint(other, b"b" * 32, self.state_outpoint(102))

    def test_contradiction_and_duplicate_confirmed_effect_are_rejected(self):
        first, ref = self.deposit()
        claimed = self.ledger.observe_deposit(first, ref, finalized=True)
        second, second_ref = self.deposit(3)
        duplicate = self.ledger.observe_deposit(second, second_ref, finalized=True)
        effect = self.ref(2)
        self.ledger.observe_mint(claimed, effect, 1024, self.owner, finalized=True)
        with self.assertRaisesRegex(ValueError, "another bridge event"):
            self.ledger.observe_mint(duplicate, effect, 1024, self.owner, finalized=True)
        with self.assertRaisesRegex(ValueError, "does not settle"):
            self.ledger.observe_mint(duplicate, self.ref(4), 1025, self.owner, finalized=True)
        self.assertEqual(self.open().state(duplicate).phase, "held")
        self.assertEqual(self.ledger.totals().unresolved_effects, 1)

    def test_uint64_accounting_uses_unsigned_values(self):
        quantity = 2**64 - 1
        deposit, ref = self.deposit(gross=quantity)
        event = self.ledger.observe_deposit(deposit, ref, finalized=True)
        self.ledger.observe_mint(event, self.ref(2), quantity, self.owner, finalized=True)
        self.assertTrue(self.ledger.reconcile(source_balance=quantity, live_supply=quantity,
                                              frozen_supply=0).may_authorize)

    def test_reconciliation_does_not_hide_unearned_fees_and_can_recover(self):
        deposit, ref = self.deposit()
        event = self.ledger.observe_deposit(deposit, ref, finalized=True)
        self.ledger.observe_mint(event, self.ref(2), 1024, self.owner, finalized=True)
        bad_entry = self.ref(3)
        self.ledger.observe_reserve_entry(bad_entry, "fee_sweep", 10)
        discrepant = self.ledger.reconcile(source_balance=1014, live_supply=1024, frozen_supply=0)
        self.assertFalse(discrepant.balanced)
        evidence = b"v" * 32
        with self.assertRaisesRegex(ValueError, "must balance"):
            self.ledger.resolve_hold(discrepant.holds[0][0], evidence,
                                     source_balance=1014, live_supply=1024, frozen_supply=0)
        self.assertTrue(self.ledger.reorg_reserve_entry(bad_entry))
        self.ledger.observe_reserve_entry(bad_entry, "fee_sweep", 10)
        restarted = self.open()
        recovered = restarted.reconcile(source_balance=1024, live_supply=1024, frozen_supply=0)
        self.assertTrue(recovered.balanced)
        self.assertFalse(recovered.may_authorize)
        for hold_id, _ in recovered.holds:
            self.assertTrue(restarted.resolve_hold(hold_id, evidence,
                                                   source_balance=1024, live_supply=1024, frozen_supply=0))
            self.assertFalse(restarted.resolve_hold(hold_id, evidence,
                                                    source_balance=1024, live_supply=1024, frozen_supply=0))
        self.assertTrue(self.ledger.reconcile(source_balance=1024, live_supply=1024,
                                              frozen_supply=0).may_authorize)
        self.assertIn("hold_resolved", {entry[2] for entry in restarted.audit_log()})

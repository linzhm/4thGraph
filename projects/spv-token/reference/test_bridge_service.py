"""Service recovery tests with finality fixtures and optional local EVM/BSV nodes."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from hashlib import new, sha256
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from bridge_ledger import BridgeLedger, ChainReference
from bridge_service import BridgeService, _RELEASE_TOPIC
from cross_chain_fixture import LocalReserve
from mint import MintPolicy, RecoveredMintState, prepare_mint
from mint_events import Deposit, DepositPosition, EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy
from evm import test_release_adapter as release_fixture
from evm import test_reserve_rpc as reserve_fixture
from evm.anvil_fixture import HAS_FOUNDRY, start_anvil
from evm.bsv_burn_evidence import BsvConfirmationPolicy, BurnEvidenceError
from evm.release_adapter import ReleaseAuthorization, ReleaseEvidenceError, Settlement
from evm.reserve_rpc import DepositEvidenceError
from regtest_mint import Node, base58check, sign_p2pkh
from shared.script import asm
from shared.transaction import Input, Output, Transaction
from statement import AssetDescriptor
from test_mint import ATTESTOR, OTHER, OWNER, public, sign


def never_sign(_digest):
    raise AssertionError("an already authorized claim reached the signer again")


class SimulatedBsvMint:
    """Models the node's adopted block and exact raw transaction responses."""

    genesis_hash = b"g" * 32

    def __init__(self, transaction):
        self.tx = transaction
        self.location = ChainReference(transaction.txid_wire(), 1, b"b" * 32, 12)
        self.active_block = self.location.block_hash
        self.tip = 12
        self.policy = BsvConfirmationPolicy(1, "regtest", self.genesis_hash, 2)

    def rpc(self, method, *params):
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": self.tip, "bestblockhash": (b"t" * 32)[::-1].hex()}
        if method == "getblockhash":
            height, = params
            if height == 0:
                return self.genesis_hash[::-1].hex()
            if height == 12:
                return self.active_block[::-1].hex()
            return (b"t" * 32)[::-1].hex()
        if method == "getblock":
            return {"hash": self.active_block[::-1].hex(), "height": 12, "tx": [self.tx.txid()]}
        if method == "getrawtransaction":
            return self.tx.serialize().hex()
        raise AssertionError(f"unexpected BSV request {method}")


class BridgeServiceTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "bridge.sqlite3"
        self.source = reserve_fixture.ReserveRpcTests()
        self.source.setUp()
        anchor = Input(b"i" * 32, 0)
        self.asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, bytes(12) + self.source.scope.reserve_asset, b"p" * 32)
        self.source.scope = replace(self.source.scope, asset_id=self.asset.asset_id())
        self.source.log["topics"][-1] = reserve_fixture.hx(self.asset.asset_id())
        self.token_policy = TokenPolicy((asm("OP_1"),), public(OTHER))
        self.mint_policy = MintPolicy(
            self.asset, self.source.scope.chain_id, self.source.scope.vault, public(ATTESTOR), self.token_policy.lock,
        )
        genesis = Transaction((anchor,), (Output(10_000, self.mint_policy.state_lock(EMPTY_ROOT)),))
        self.current = RecoveredMintState(genesis, MintEvents(), False)
        position = DepositPosition(self.mint_policy.source_chain_id, self.asset.reserve_domain,
                                   self.mint_policy.reserve_contract, self.source.tx_hash, 1)
        self.deposit = Deposit(position, self.asset.reserve_asset, self.asset.network, self.asset.asset_id(),
                               1024, 0, self.source.owner)
        self.plan = prepare_mint(self.mint_policy, genesis, MintEvents(), self.deposit, Input(b"s" * 32, 0))
        self.event = position.event_id()

    def service(self, *, read=None):
        scope = self.source.scope
        ledger = BridgeLedger(self.path, self.asset, scope.chain_id, scope.vault)
        return BridgeService(ledger, self.mint_policy, scope, read or self.source.rpc)

    def another_deposit(self):
        txid = b"u" * 32
        hx = reserve_fixture.hx
        receipt = deepcopy(self.source.receipt)
        index = hex(len(self.source.canonical["transactions"]))
        self.source.canonical["transactions"].append(hx(txid))
        receipt.update(transactionHash=hx(txid), transactionIndex=index)
        for log in receipt["logs"]:
            log.update(transactionHash=hx(txid), transactionIndex=index,
                       logIndex=hex(int(log["logIndex"], 16) + 2))
        self.source.rpc_values[("eth_getTransactionReceipt", hx(txid))] = receipt
        return replace(self.deposit, position=replace(self.deposit.position, transaction_hash=txid))

    def test_recovery_across_signed_intent_confirmation_and_reorg(self):
        service = self.service()
        source_final = self.source.finalized["number"]
        self.source.finalized["number"] = "0x9"
        with self.assertRaisesRegex(DepositEvidenceError, "not finalized"):
            service.authorize_mint(self.plan, lambda: self.current, never_sign)
        self.assertIsNone(service.ledger.state(self.event))
        self.source.finalized["number"] = source_final

        def signing_rpc_times_out(digest):
            state = self.service().ledger.state(self.event)
            self.assertEqual((state.phase, state.authorization), ("authorized", digest))
            raise TimeoutError("test signer transport interrupted")

        with self.assertRaises(TimeoutError):
            service.authorize_mint(self.plan, lambda: self.current, signing_rpc_times_out)
        restarted = self.service()
        authorized = restarted.recover_mint(self.event, lambda: self.current, sign)
        self.assertEqual(authorized, self.service().recover_mint(self.event, lambda: self.current, never_sign))
        pending = restarted.reconcile(source_balance=1024, live_supply=0, frozen_supply=0)
        self.assertEqual(pending.totals.pending_mint, 1024)
        self.assertIsNone(restarted.ledger.state(self.event).effect)

        bsv = SimulatedBsvMint(authorized)
        with self.assertRaisesRegex(BurnEvidenceError, "confirmation policy"):
            restarted.record_mint(bsv.rpc, bsv.policy, bsv.location, self.current)
        self.assertEqual(restarted.ledger.state(self.event).phase, "authorized")
        bsv.tip = 13
        self.assertEqual(restarted.record_mint(bsv.rpc, bsv.policy, bsv.location, self.current), self.event)
        settled = self.service().reconcile(source_balance=1024, live_supply=1024, frozen_supply=0)
        self.assertTrue(settled.balanced)
        self.assertEqual(settled.totals.pending_mint, 0)

        self.source.canonical["hash"] = reserve_fixture.hx(b"z" * 32)
        with self.assertRaisesRegex(ValueError, "recorded EVM block was replaced"):
            self.service().authorize_mint(self.plan, lambda: self.current, never_sign)
        self.assertEqual(self.service().ledger.state(self.event).phase, "held")
        self.assertFalse(self.service().reconcile(source_balance=0, live_supply=1024, frozen_supply=0).may_authorize)

    def test_invalid_signer_and_manual_hold_are_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "current confirmed mint state"):
            self.service().authorize_mint(self.plan, lambda: replace(self.current, paused=True), never_sign)
        with self.assertRaisesRegex(ValueError, "invalid signature"):
            self.service().authorize_mint(self.plan, lambda: self.current, lambda _: b"wrong")
        self.assertEqual(self.service().ledger.state(self.event).phase, "authorized")
        self.service().pause("operator investigation", b"p" * 32)
        with self.assertRaisesRegex(ValueError, "held for review"):
            self.service().authorize_mint(self.plan, lambda: self.current, never_sign)

    def test_concurrent_claim_retries_use_one_verified_signature(self):
        calls = []

        def signer(digest):
            calls.append(digest)
            return sign(digest)

        with ThreadPoolExecutor(max_workers=4) as workers:
            signed = tuple(workers.map(
                lambda _: self.service().authorize_mint(self.plan, lambda: self.current, signer), range(8),
            ))
        self.assertEqual(len(calls), 1)
        self.assertEqual(len({tx.txid_wire() for tx in signed}), 1)
        record = self.service().ledger.state(self.event)
        self.assertEqual((record.phase, record.authorization), ("authorized", calls[0]))

    def test_retry_preserves_draft_even_when_sponsor_unlock_is_outside_digest(self):
        signed = self.service().authorize_mint(self.plan, lambda: self.current, sign)
        replaced_sponsor = replace(self.plan.transaction.inputs[1], script=asm("OP_1"))
        changed_draft = prepare_mint(self.mint_policy, self.current.transaction, self.current.events,
                                     self.deposit, replaced_sponsor)
        with self.assertRaisesRegex(ValueError, "mint retry differs from the recorded transaction draft"):
            self.service().authorize_mint(changed_draft, lambda: self.current, never_sign)
        self.assertEqual(self.service().recover_mint(self.event, lambda: self.current, never_sign), signed)

    def test_distinct_claim_waits_across_crash_and_replans_after_confirmation(self):
        waiting = self.another_deposit()
        waiting_id = waiting.position.event_id()
        competing = prepare_mint(self.mint_policy, self.current.transaction, self.current.events,
                                 waiting, Input(b"v" * 32, 0))

        def lose_signer_reply(_digest):
            raise TimeoutError("signer may have signed before the response was lost")

        with self.assertRaises(TimeoutError):
            self.service().authorize_mint(self.plan, lambda: self.current, lose_signer_reply)
        with self.assertRaisesRegex(ValueError, "another mint already reserved this state outpoint"):
            self.service().authorize_mint(competing, lambda: self.current, never_sign)
        blocked = self.service().ledger.state(waiting_id)
        self.assertEqual((blocked.phase, blocked.authorization), ("finalized", None))

        signed = self.service().authorize_mint(self.plan, lambda: self.current, sign)
        self.assertEqual(self.service().authorize_mint(self.plan, lambda: self.current, never_sign), signed)
        bsv = SimulatedBsvMint(signed)
        bsv.tip = 13
        self.service().record_mint(bsv.rpc, bsv.policy, bsv.location, self.current)
        advanced = RecoveredMintState(signed, self.plan.successor, False)
        with self.assertRaisesRegex(ValueError, "current confirmed mint state"):
            self.service().authorize_mint(competing, lambda: advanced, never_sign)
        replanned = prepare_mint(self.mint_policy, advanced.transaction, advanced.events,
                                 waiting, competing.transaction.inputs[1])
        retry = self.service().authorize_mint(replanned, lambda: advanced, sign)
        self.assertEqual(retry.inputs[0].txid, signed.txid_wire())
        self.assertIsNotNone(self.service().ledger.state(waiting_id).authorization)

    def test_distinct_concurrent_claims_never_share_a_state_authorization(self):
        waiting = self.another_deposit()
        competing = prepare_mint(self.mint_policy, self.current.transaction, self.current.events,
                                 waiting, Input(b"v" * 32, 0))
        calls = []

        def signer(digest):
            calls.append(digest)
            return sign(digest)

        def attempt(plan):
            try:
                return self.service().authorize_mint(plan, lambda: self.current, signer)
            except ValueError as error:
                self.assertIn("another mint already reserved this state outpoint", str(error))
                return None

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = tuple(workers.map(attempt, (self.plan, competing)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(calls), 1)

    def test_release_recovers_exact_signature_and_separately_ingests_receipt(self):
        fixture = release_fixture.ReleaseAdapterTest()
        fixture.setUp()
        fixture.asset, fixture.scope = self.asset, self.source.scope
        fixture._reset_burn(b"r" * 20)
        fixture.active_hash = fixture.reference.block_hash
        fixture.returned_token = fixture.scope.reserve_asset

        class RecognizedBurn:
            mint_policy = self.mint_policy

            def burn(self, txid, vout):
                if (txid, vout) != (fixture.reference.txid, fixture.reference.vout):
                    raise ValueError("unrecognized fixture burn")
                return fixture.burn

        methods = {}
        # Keep the mapping lookup restricted to receipt data requests (eth_call has dict arguments).
        def evm(method, *params):
            if method != "eth_call" and (method, *params) in methods:
                return methods[(method, *params)]
            return fixture.evm_rpc(method, *params)

        authorize = lambda signer: self.service(read=evm).authorize_release(
            fixture.bsv_rpc, fixture.policy, fixture.reference, RecognizedBurn(), signer,
        )
        release = authorize(fixture.signer_callback)
        self.assertIsInstance(release, ReleaseAuthorization)
        burn_id = release_fixture.burn_event_id(self.asset.network, fixture.reference)
        self.assertEqual(self.service().ledger.state(burn_id).phase, "authorized")
        self.assertEqual(authorize(never_sign), release)
        self.assertEqual(len(fixture.signer_calls), 1)

        fixture.latest_digest = release.digest
        observed = authorize(never_sign)
        self.assertIsInstance(observed, Settlement)
        self.assertFalse(observed.finalized)
        self.assertEqual(self.service().ledger.state(burn_id).phase, "authorized")

        ref = ChainReference(b"t" * 32, 0, b"l" * 32, 10)
        hx, word = release_fixture.hx, release_fixture.word
        fields = {"transactionHash": hx(ref.txid), "blockHash": hx(ref.block_hash), "blockNumber": "0xa",
                  "transactionIndex": "0x0"}
        log = {**fields, "address": hx(fixture.scope.vault), "removed": False, "logIndex": "0x0",
               "topics": [hx(_RELEASE_TOPIC), hx(burn_id), hx(fixture.reference.txid), hx(bytes(12) + fixture.burn.recipient)],
               "data": hx(word(fixture.reference.vout) + word(fixture.burn.quantity) + word(fixture.burn.fee) + release.digest)}
        methods[("eth_getTransactionReceipt", hx(ref.txid))] = {**fields, "status": "0x1", "logs": [log]}
        methods[("eth_getBlockByNumber", "0xa", False)] = {"number": "0xa", "hash": hx(ref.block_hash),
                                                          "transactions": [hx(ref.txid)]}
        ingested = self.service(read=evm).record_release(ref, fixture.reference)
        self.assertEqual(ingested.phase, "submitted")
        fixture.finalized_digest = release.digest
        methods[("eth_getBlockByNumber", "finalized", False)] = {"number": "0xa", "hash": hx(b"f" * 32)}
        with self.assertRaisesRegex(ReleaseEvidenceError, "inconsistent"):
            self.service(read=evm).record_release(ref, fixture.reference)
        self.assertEqual(self.service().ledger.state(burn_id).phase, "submitted")
        methods[("eth_getBlockByNumber", "finalized", False)] = {"number": "0xa", "hash": hx(ref.block_hash)}
        final = self.service(read=evm).record_release(ref, fixture.reference)
        self.assertEqual(final.phase, "settled")
        self.assertEqual(len(fixture.signer_calls), 1)
        fixture.active_hash = b"n" * 32
        with self.assertRaisesRegex(ValueError, "recorded BSV block was replaced"):
            authorize(never_sign)
        self.assertEqual(self.service().ledger.state(burn_id).phase, "held")


@unittest.skipUnless(HAS_FOUNDRY and os.environ.get("CCTP_MINT_REGTEST_COOKIE"),
                     "requires Foundry plus an independent BSV regtest")
class LiveBridgeServiceTest(unittest.TestCase):
    def test_anvil_deposit_bsv_mint_finality_and_service_restart(self):
        owner = public(OWNER)
        address = base58check(b"\x6f" + new("ripemd160", sha256(owner).digest()).digest())
        node = Node(os.environ.get("CCTP_MINT_REGTEST_URL", "http://127.0.0.1:19444"),
                    Path(os.environ["CCTP_MINT_REGTEST_COOKIE"]))
        coin = node.fund(address)
        funding = Transaction((Input(coin.txid_wire(), 0),), (Output(200_000, asm("OP_1")),) * 3)
        funding = sign_p2pkh(funding, coin, 0, OWNER)
        node.confirm(funding, address)
        anchor, sponsor, second_sponsor = (Input(funding.txid_wire(), i) for i in range(3))

        with TemporaryDirectory() as directory, start_anvil() as evm:
            reserve = LocalReserve(evm, anchor.outpoint())
            asset, scope = reserve.asset, reserve.scope
            tokens = TokenPolicy((asm("OP_1"),), public(OTHER))
            mint_policy = MintPolicy(asset, scope.chain_id, scope.vault, public(ATTESTOR), tokens.lock)
            path = Path(directory) / "bridge.sqlite3"

            def restart():
                ledger = BridgeLedger(path, asset, scope.chain_id, scope.vault)
                return BridgeService(ledger, mint_policy, scope, evm.rpc)

            genesis = Transaction((anchor,), (Output(100_000, mint_policy.state_lock(EMPTY_ROOT)),))
            node.confirm(genesis, address)
            current = RecoveredMintState(genesis, MintEvents(), False)
            deposit, _ = reserve.deposit(1024, owner)
            second_deposit, _ = reserve.deposit(384, owner)
            plan = prepare_mint(mint_policy, genesis, current.events, deposit, sponsor)
            competing = prepare_mint(mint_policy, genesis, current.events, second_deposit, second_sponsor)
            event = deposit.position.event_id()
            second_event = second_deposit.position.event_id()
            tx = restart().authorize_mint(plan, lambda: current, sign)
            self.assertEqual(restart().recover_mint(event, lambda: current, never_sign), tx)
            with self.assertRaisesRegex(ValueError, "another mint already reserved this state outpoint"):
                restart().authorize_mint(competing, lambda: current, never_sign)
            self.assertEqual(restart().ledger.state(event).phase, "authorized")
            node.confirm(tx, address)
            record = node.call("getrawtransaction", tx.txid(), True)
            header = node.call("getblockheader", record["blockhash"], True)
            reference = ChainReference(tx.txid_wire(), 1, bytes.fromhex(record["blockhash"])[::-1], header["height"])
            policy = BsvConfirmationPolicy(asset.network, "regtest", bytes.fromhex(node.call("getblockhash", 0))[::-1], 2)
            with self.assertRaisesRegex(BurnEvidenceError, "confirmation policy"):
                restart().record_mint(node.call, policy, reference, current)
            node.call("generatetoaddress", 1, address)
            restart().record_mint(node.call, policy, reference, current)
            self.assertEqual(restart().ledger.state(event).phase, "settled")
            advanced = RecoveredMintState(tx, plan.successor, False)
            next_plan = prepare_mint(mint_policy, tx, plan.successor, second_deposit, second_sponsor)
            second = restart().authorize_mint(next_plan, lambda: advanced, sign)
            node.confirm(second, address)
            node.call("generatetoaddress", 1, address)
            second_record = node.call("getrawtransaction", second.txid(), True)
            second_header = node.call("getblockheader", second_record["blockhash"], True)
            second_reference = ChainReference(
                second.txid_wire(), 1, bytes.fromhex(second_record["blockhash"])[::-1], second_header["height"],
            )
            restart().record_mint(node.call, policy, second_reference, advanced)
            self.assertEqual(restart().ledger.state(second_event).phase, "settled")
            source_balance = int(evm.call(reserve.vault, "netReserve()(uint256)"), 0)
            live_supply = sum(tokens.parse(Transaction.parse(bytes.fromhex(row["hex"])).outputs[1].script).quantity
                              for row in (record, second_record))
            report = restart().reconcile(source_balance=source_balance, live_supply=live_supply, frozen_supply=0)
            self.assertTrue(report.may_authorize)

            node.call("invalidateblock", record["blockhash"])
            try:
                for removed in (event, second_event):
                    with self.assertRaisesRegex(ValueError, "recorded BSV block was replaced"):
                        restart().recheck_mint_effect(node.call, policy, removed)
                journal = restart()
                self.assertEqual(journal.ledger.state(event).phase, "held")
                recovered = journal.reconcile(source_balance=source_balance, live_supply=0, frozen_supply=0)
                self.assertTrue(recovered.balanced)
                self.assertFalse(recovered.may_authorize)
                self.assertEqual(recovered.totals.pending_mint, 1408)
            finally:
                node.call("reconsiderblock", record["blockhash"])

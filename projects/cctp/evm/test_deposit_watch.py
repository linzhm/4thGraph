"""Finalized-scan restart, receipt matching and live loopback EVM tests."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from bridge_ledger import BridgeLedger
from bridge_service import BridgeService
from mint import MintPolicy
from mint_events import DepositPosition
from shared.script import asm
from statement import AssetDescriptor

from projects.cctp.evm.anvil_fixture import HAS_FOUNDRY, deposit_position, start_anvil
from projects.cctp.evm.deposit_watch import DepositWatchReorg, DepositWatcher
from projects.cctp.evm.release_adapter import _address, _hash, _hex, _word
from projects.cctp.evm.reserve_rpc import DEPOSIT_TOPIC, DepositEvidenceError, ReserveScope

OWNER = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")


def bridge(path, asset, scope, rpc):
    mint = MintPolicy(asset, scope.chain_id, scope.vault, OWNER, lambda _: asm("OP_1"))
    return BridgeService(BridgeLedger(path, asset, scope.chain_id, scope.vault), mint, scope, rpc)


class LocalLogRpc:
    def __init__(self, scope):
        self.scope = scope
        self.chain_id = scope.chain_id
        self.txid = b"t" * 32
        self.depositor = b"p" * 20
        self.head = 8
        self.hashes = {h: sha256(b"block" + bytes([h])).digest() for h in range(20)}
        self.fork = None
        self.logs_mode = "normal"
        self.log_requests = []
        self.receipt_requests = 0
        self.scope_asset = scope.asset_id
        self.nonces = {h: 0 if h < 10 else 2 for h in self.hashes}
        self.logs = self._logs()

    def _logs(self):
        common = {
            "blockHash": _hex(self.hashes[10]), "blockNumber": "0xa",
            "transactionHash": _hex(self.txid), "transactionIndex": "0x1", "removed": False,
        }

        def deposit(index, nonce, quantity):
            data = (
                _word(self.scope.reserve_domain) + _word(self.scope.bsv_network)
                + _address(self.scope.reserve_asset) + _word(quantity) + _word(160) + _word(33) + OWNER + bytes(31)
            )
            return common | {
                "address": _hex(self.scope.vault), "logIndex": hex(index),
                "topics": [_hex(DEPOSIT_TOPIC), _hex(_word(nonce)), _hex(_address(self.depositor)),
                           _hex(self.scope.asset_id)],
                "data": _hex(data),
            }

        def transfer(index):
            return common | {"address": _hex(self.scope.reserve_asset), "logIndex": hex(index),
                             "topics": [], "data": "0x"}

        return [transfer(12), deposit(13, 1, 1024), transfer(14), deposit(15, 2, 384)]

    def replace_branch(self, first):
        self.fork = first
        for h in range(first, 20):
            self.hashes[h] = sha256(b"replacement" + bytes([h])).digest()
            self.nonces[h] = 0

    def __call__(self, method, *args):
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            tag, full = args
            assert full is False
            height = self.head if tag == "finalized" else int(tag, 16)
            return {
                "number": hex(height), "hash": _hex(self.hashes[height]),
                "transactions": [_hex(b"x" * 32), _hex(self.txid)] if height == 10 else [],
            }
        if method == "eth_call":
            call, pin = args
            assert pin["requireCanonical"] and call["to"] == _hex(self.scope.vault)
            height, = [h for h, digest in self.hashes.items() if _hex(digest) == pin["blockHash"]]
            selectors = {
                b"deploymentChainId()": _word(self.scope.chain_id),
                b"reserveDomain()": _word(self.scope.reserve_domain),
                b"bsvNetwork()": _word(self.scope.bsv_network),
                b"assetId()": self.scope_asset,
                b"token()": _address(self.scope.reserve_asset),
                b"depositNonce()": _word(self.nonces[height]),
            }
            for name, value in selectors.items():
                if call["data"] == _hex(_hash(name)[:4]):
                    if name == b"depositNonce()" and height < 9:
                        return "0x"
                    return _hex(value)
        if method == "eth_getLogs":
            query, = args
            assert query["address"] == _hex(self.scope.vault) and query["topics"] == [_hex(DEPOSIT_TOPIC)]
            start, end = int(query["fromBlock"], 16), int(query["toBlock"], 16)
            self.log_requests.append((start, end))
            if not start <= 10 <= end or (self.fork is not None and self.fork <= 10):
                return []
            logs = [deepcopy(self.logs[i]) for i in (1, 3)]
            if self.logs_mode == "duplicate_reordered":
                logs = [logs[1], logs[0], deepcopy(logs[0])]
            elif self.logs_mode == "truncated":
                logs.pop()
            elif self.logs_mode == "altered":
                logs[0]["data"] = logs[0]["data"][:-2] + "01"
            return logs
        if method == "eth_getTransactionReceipt":
            self.receipt_requests += 1
            assert args == (_hex(self.txid),)
            return {
                "status": "0x1", "transactionHash": _hex(self.txid),
                "blockHash": self.logs[0]["blockHash"], "blockNumber": "0xa",
                "transactionIndex": "0x1", "logs": self.logs,
            }
        raise AssertionError(f"unexpected RPC method {method}")


class DepositWatchTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "ledger.sqlite3"
        self.asset = AssetDescriptor(1, b"i" * 36, 6, 7, bytes(12) + b"u" * 20, b"p" * 32)
        self.scope = ReserveScope(84532, 7, 1, b"v" * 20, b"u" * 20, self.asset.asset_id())
        self.rpc = LocalLogRpc(self.scope)
        self.ids = tuple(DepositPosition(84532, 7, self.scope.vault, self.rpc.txid, i).event_id() for i in (1, 3))

    def restart(self, *, start=9, max_blocks=2, max_events=10):
        service = bridge(self.path, self.asset, self.scope, self.rpc)
        return DepositWatcher(service, start, max_blocks=max_blocks, max_events=max_events)

    def _check_unstarted(self, watcher):
        cursor, pending = watcher._progress()
        self.assertEqual(cursor.height, 8)
        self.assertIsNone(pending)
        self.assertEqual(watcher.service.ledger.totals().finalized_deposits, 0)

    def test_bounded_catch_up_orders_events_and_uses_receipt_ordinals(self):
        watcher = self.restart()
        initial = watcher.scan_once()
        self.assertEqual((initial.first_height, initial.scanned_through, initial.event_ids), (None, 8, ()))
        self.assertEqual(self.rpc.log_requests, [])

        self.rpc.head = 13
        self.rpc.logs_mode = "duplicate_reordered"
        first = watcher.scan_once()
        self.assertEqual((first.first_height, first.scanned_through, first.event_ids), (9, 10, self.ids))
        self.assertEqual(self.rpc.receipt_requests, 1)
        self.assertEqual(self.rpc.log_requests, [(9, 10)])
        for ordinal, event_id in zip((1, 3), self.ids, strict=True):
            state = watcher.service.ledger.state(event_id)
            self.assertEqual((state.phase, state.origin.position), ("finalized", ordinal))
            self.assertIsNone(state.authorization)
        self.assertEqual(watcher.service.ledger.totals().pending_mint, 1408)

        restart = self.restart()
        self.assertEqual(restart.scan_once().scanned_through, 12)
        self.assertEqual(restart.scan_once().scanned_through, 13)
        self.assertIsNone(self.restart().scan_once().first_height)
        self.assertEqual(self.rpc.log_requests, [(9, 10), (11, 12), (13, 13)])
        with self.assertRaisesRegex(ValueError, "different start height"):
            self.restart(start=10)

    def test_concurrent_watchers_commit_distinct_ranges(self):
        self.rpc.head = 12
        watchers = (self.restart(), self.restart())
        with ThreadPoolExecutor(max_workers=2) as executor:
            reports = tuple(executor.map(lambda watcher: watcher.scan_once(), watchers))
        self.assertEqual({(item.first_height, item.scanned_through) for item in reports}, {(9, 10), (11, 12)})
        self.assertEqual(self.rpc.log_requests, [(9, 10), (11, 12)])
        self.assertEqual(watchers[0].service.ledger.totals().finalized_deposits, 1408)

    def test_incomplete_or_altered_log_result_cannot_advance_or_partially_persist(self):
        self.rpc.head = 10
        watcher = self.restart()
        self.rpc.logs_mode = "altered"
        with self.assertRaisesRegex(DepositEvidenceError, "exact receipt"):
            watcher.scan_once()
        self._check_unstarted(watcher)
        self.rpc.logs_mode = "truncated"
        with self.assertRaisesRegex(DepositEvidenceError, "incomplete finalized log discovery"):
            watcher.scan_once()
        self._check_unstarted(watcher)
        self.rpc.logs_mode = "normal"
        self.assertEqual(self.restart().scan_once().event_ids, self.ids)

    def test_restarts_staged_range_after_partial_journal_write(self):
        self.rpc.head = 10
        watcher = self.restart()
        ledger = watcher.service.ledger
        observe = ledger.observe_deposit
        failed = False

        def break_second(deposit, *args, **kwargs):
            nonlocal failed
            if deposit.position.event_id() == self.ids[1]:
                failed = True
                raise OSError("test interrupted before second journal write")
            return observe(deposit, *args, **kwargs)

        with patch.object(ledger, "observe_deposit", side_effect=break_second):
            with self.assertRaisesRegex(OSError, "second journal write"):
                watcher.scan_once()
        self.assertTrue(failed)
        cursor, pending = watcher._progress()
        self.assertEqual((cursor.height, pending.height), (8, 10))
        self.assertEqual(ledger.totals().finalized_deposits, 1024)

        result = self.restart().scan_once()
        after = self.restart()
        self.assertEqual(result.event_ids, self.ids)
        self.assertEqual(after.service.ledger.totals().finalized_deposits, 1408)
        self.assertIsNone(after._progress()[1])

    def test_replacement_of_staged_range_holds_bridge_and_orphans_exact_partial_write(self):
        self.rpc.head = 10
        watcher = self.restart()
        ledger = watcher.service.ledger
        observe = ledger.observe_deposit

        def write_then_fail(deposit, *args, **kwargs):
            observe(deposit, *args, **kwargs)
            raise OSError("after the first durable write")

        with patch.object(ledger, "observe_deposit", side_effect=write_then_fail):
            with self.assertRaisesRegex(OSError, "first durable write"):
                watcher.scan_once()
        self.rpc.replace_branch(10)
        with self.assertRaisesRegex(DepositWatchReorg, "held"):
            self.restart().scan_once()
        self.assertEqual(self.restart()._progress()[0].height, 8)
        self.assertEqual(ledger.state(self.ids[0]).phase, "orphaned")
        self.assertIsNone(ledger.state(self.ids[1]))
        status = ledger.reconcile(source_balance=0, live_supply=0, frozen_supply=0)
        self.assertTrue(status.balanced)
        self.assertFalse(status.may_authorize)

    def test_rechecks_finalized_history_and_distinguishes_a_lagging_provider(self):
        self.rpc.head = 10
        watcher = self.restart()
        watcher.scan_once()
        self.rpc.head = 9
        with self.assertRaisesRegex(DepositEvidenceError, "behind"):
            watcher.scan_once()
        ledger = watcher.service.ledger
        self.assertTrue(ledger.reconcile(source_balance=1408, live_supply=0, frozen_supply=0).may_authorize)
        self.rpc.head = 10
        self.assertTrue(watcher.recheck_recorded(self.ids[0]))
        self.rpc.replace_branch(10)
        with self.assertRaisesRegex(DepositWatchReorg, "held"):
            watcher.scan_once()
        with self.assertRaisesRegex(DepositWatchReorg, "held"):
            watcher.recheck_recorded(self.ids[0])
        self.assertEqual(ledger.state(self.ids[0]).phase, "orphaned")
        self.assertFalse(ledger.reconcile(source_balance=384, live_supply=0, frozen_supply=0).may_authorize)

    def test_rejects_wrong_scope_chain_and_late_start(self):
        self.rpc.head = 12
        watcher = self.restart()
        self.rpc.chain_id = 1
        with self.assertRaisesRegex(DepositEvidenceError, "chain"):
            watcher.scan_once()
        self.rpc.chain_id = self.scope.chain_id
        self.rpc.scope_asset = b"e" * 32
        with self.assertRaisesRegex(DepositEvidenceError, "reserve scope"):
            watcher.scan_once()
        self.rpc.scope_asset = self.scope.asset_id
        with TemporaryDirectory() as other:
            service = bridge(Path(other) / "ledger", self.asset, self.scope, self.rpc)
            with self.assertRaisesRegex(DepositEvidenceError, "after an existing"):
                DepositWatcher(service, 11).scan_once()

    @unittest.skipUnless(HAS_FOUNDRY, "requires Foundry")
    def test_loopback_anvil_finalized_reserve_log_reaches_durable_ledger(self):
        from cross_chain_fixture import LocalReserve
        from projects.cctp.evm.anvil_fixture import _command

        with start_anvil() as evm:
            reserve = LocalReserve(evm, self.asset.issuance_outpoint)
            start = int(evm.rpc("eth_getBlockByNumber", "latest", False)["number"], 16)
            watcher = DepositWatcher(bridge(self.path, reserve.asset, reserve.scope, evm.rpc), start)
            snapshot = json.loads(_command("cast", "rpc", "--rpc-url", evm.url, "evm_snapshot"))
            evm.send(reserve.usdc, "mint(address,uint256)", reserve.depositor, "1024", sender=reserve.admin)
            evm.send(reserve.usdc, "approve(address,uint256)", reserve.vault, "1024", sender=reserve.depositor)
            receipt = evm.send(reserve.vault, "deposit(uint64,bytes)", "1024", _hex(OWNER), sender=reserve.depositor)
            self.assertEqual(watcher.scan_once().event_ids, ())
            event = deposit_position(receipt, reserve.vault)
            self.assertEqual(event.log_ordinal, 1)
            evm.mine_finality()
            fresh = DepositWatcher(bridge(self.path, reserve.asset, reserve.scope, evm.rpc), start)
            self.assertEqual(fresh.scan_once().event_ids, (event.event_id(),))
            ledger = fresh.service.ledger
            self.assertEqual(ledger.totals().pending_mint, 1024)
            state = ledger.state(event.event_id())
            self.assertEqual(state.origin.position, 1)
            self.assertIsNone(state.authorization)
            self.assertEqual(fresh.scan_once().event_ids, ())

            # Replace the finalized history on this disposable loopback node.
            reverted = _command("cast", "rpc", "--rpc-url", evm.url, "evm_revert", snapshot)
            self.assertTrue(json.loads(reverted))
            _command("cast", "rpc", "--rpc-url", evm.url, "anvil_mine", "0x55")
            with self.assertRaises(DepositWatchReorg):
                fresh.scan_once()
            with self.assertRaises(DepositWatchReorg):
                fresh.recheck_recorded(event.event_id())
            self.assertEqual(ledger.state(event.event_id()).phase, "orphaned")
            reconciled = ledger.reconcile(source_balance=0, live_supply=0, frozen_supply=0)
            self.assertTrue(reconciled.balanced)
            self.assertFalse(reconciled.may_authorize)


if __name__ == "__main__":
    unittest.main()

"""Restart-safe scan of finalized reserve deposits into a bridge ledger."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import os
import sqlite3

from bridge_ledger import ChainReference
from bridge_service import BridgeService
from mint_events import Deposit, DepositPosition
from statement import uint

from projects.cctp.evm.release_adapter import _address, _hash, _hex, _word
from projects.cctp.evm.reserve_rpc import (
    DEPOSIT_TOPIC, DepositEvidenceError, _data, _object, _quantity, read_finalized_deposit,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS evm_deposit_watch_cursor_v1 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    start_height INTEGER NOT NULL,
    height INTEGER NOT NULL,
    hash BLOB,
    nonce BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS evm_deposit_watch_batch_v1 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    height INTEGER NOT NULL,
    hash BLOB NOT NULL,
    nonce BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS evm_deposit_watch_delivery_v1 (
    ordinal INTEGER PRIMARY KEY,
    event_id BLOB NOT NULL UNIQUE,
    reference BLOB NOT NULL,
    payload_hash BLOB NOT NULL
);
"""


class DepositWatchReorg(DepositEvidenceError):
    """A previously finalized block was replaced and the bridge was put on hold."""


@dataclass(frozen=True)
class _Block:
    height: int
    hash: bytes


@dataclass(frozen=True)
class _Cursor:
    height: int
    hash: bytes | None
    nonce: int


@dataclass(frozen=True)
class _DiscoveredLog:
    height: int
    log_index: int
    block_hash: bytes
    txid: bytes
    transaction_index: int
    emitter: bytes
    topics: tuple[bytes, ...]
    data: bytes


@dataclass(frozen=True)
class DepositScan:
    first_height: int | None
    scanned_through: int
    finalized_height: int
    event_ids: tuple[bytes, ...]


class DepositWatcher:
    """Deliver a bounded finalized range per call, independent of authorization.

    Use the vault deployment block as start_height. The trusted RPC must
    provide historical finalized state and canonical block-hash eth_call.
    Checkpoint and in-flight deliveries share the bridge's durable SQLite file.
    Call scan_once again to catch up or after reopening the service. On
    DepositWatchReorg stop polling and review the held ledger; a confirmed-chain
    replacement never advances the cursor automatically.
    """

    def __init__(
        self, service: BridgeService, start_height: int, *, max_blocks: int = 128, max_events: int = 1024,
    ):
        uint(start_height, 4)
        if type(max_blocks) is not int or not 1 <= max_blocks <= 2000:
            raise ValueError("max_blocks must be between 1 and 2000")
        if type(max_events) is not int or not 1 <= max_events <= 4096:
            raise ValueError("max_events must be between 1 and 4096")
        self.service = service
        self.start_height = start_height
        self.max_blocks = max_blocks
        self.max_events = max_events
        self.scope = service.reserve_scope
        self.path = service.ledger.path
        with self._lock(), self._db() as conn:
            conn.executescript(_SCHEMA)
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO evm_deposit_watch_cursor_v1 VALUES (1, ?, ?, NULL, ?)",
                    (start_height, start_height - 1, uint(0, 8)),
                )
                actual = conn.execute("SELECT start_height FROM evm_deposit_watch_cursor_v1").fetchone()[0]
                if actual != start_height:
                    raise ValueError("deposit watcher is already configured with a different start height")

    @contextmanager
    def _lock(self):
        fd = os.open(self.path + ".evm-deposit-watch.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(self.path, timeout=15)
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _row_cursor(row):
        if row is None:
            return None
        height, block_hash, nonce = row
        return _Cursor(height, block_hash, int.from_bytes(nonce, "little"))

    def _progress(self):
        with self._db() as conn:
            cursor = conn.execute("SELECT height, hash, nonce FROM evm_deposit_watch_cursor_v1").fetchone()
            staged = conn.execute("SELECT height, hash, nonce FROM evm_deposit_watch_batch_v1").fetchone()
        return self._row_cursor(cursor), self._row_cursor(staged)

    def _rpc(self, method, *args):
        return self.service.evm_rpc(method, *args)

    def _block(self, tag):
        block = _object(self._rpc("eth_getBlockByNumber", tag, False), "watcher block")
        height = _quantity(block.get("number"), "watcher block height")
        digest = _data(block.get("hash"), 32, "watcher block hash")
        if not any(digest) or height >= (1 << 32) or (tag != "finalized" and tag != hex(height)):
            raise DepositEvidenceError("invalid watcher block")
        return _Block(height, digest)

    def _head(self):
        if _quantity(self._rpc("eth_chainId"), "RPC chain ID") != self.scope.chain_id:
            raise DepositEvidenceError("RPC chain does not match the watcher reserve scope")
        head = self._block("finalized")
        if self._block(hex(head.height)) != head:
            raise DepositEvidenceError("finalized head disagrees with canonical height")
        return head

    def _call(self, block, selector):
        call = {"to": _hex(self.scope.vault), "data": _hex(_hash(selector)[:4])}
        return self._rpc("eth_call", call, {"blockHash": _hex(block.hash), "requireCanonical": True})

    def _check_scope(self, head):
        expected = (
            (b"deploymentChainId()", _word(self.scope.chain_id)),
            (b"reserveDomain()", _word(self.scope.reserve_domain)),
            (b"bsvNetwork()", _word(self.scope.bsv_network)),
            (b"assetId()", self.scope.asset_id),
            (b"token()", _address(self.scope.reserve_asset)),
        )
        for signature, value in expected:
            if _data(self._call(head, signature), 32, "finalized reserve scope") != value:
                raise DepositEvidenceError("finalized vault does not match the watcher reserve scope")

    def _nonce(self, block, *, before_start=False):
        word = self._call(block, b"depositNonce()")
        if before_start and word == "0x":
            return 0
        nonce = int.from_bytes(_data(word, 32, "finalized vault deposit nonce"), "big")
        if nonce >= (1 << 64):
            raise DepositEvidenceError("vault deposit nonce outside uint64")
        return nonce

    def _checkpoint(self, block, nonce, *, finish=False):
        with self._db() as conn, conn:
            conn.execute("UPDATE evm_deposit_watch_cursor_v1 SET height = ?, hash = ?, nonce = ?",
                         (block.height, block.hash, uint(nonce, 8)))
            if finish:
                conn.execute("DELETE FROM evm_deposit_watch_delivery_v1")
                conn.execute("DELETE FROM evm_deposit_watch_batch_v1")

    def _stage(self, block, nonce, deliveries, *, recovering):
        rows = [
            (i, deposit.position.event_id(), reference.encode(), sha256(deposit.encode()).digest())
            for i, (deposit, reference) in enumerate(deliveries)
        ]
        with self._db() as conn, conn:
            if recovering:
                saved = conn.execute(
                    "SELECT ordinal, event_id, reference, payload_hash FROM evm_deposit_watch_delivery_v1 ORDER BY ordinal",
                ).fetchall()
                if saved != rows:
                    raise DepositEvidenceError("rescanned finalized range differs from its pending deliveries")
            else:
                conn.execute("INSERT INTO evm_deposit_watch_batch_v1 VALUES (1, ?, ?, ?)",
                             (block.height, block.hash, uint(nonce, 8)))
                conn.executemany("INSERT INTO evm_deposit_watch_delivery_v1 VALUES (?, ?, ?, ?)", rows)

    def _pause_for_replacement(self, expected, actual, head, *, recorded=None):
        evidence = sha256(b"BSV/CCTP/watcher-reorg/v1" + uint(expected.height, 4)
                          + expected.hash + actual.hash).digest()
        self.service.pause("finalized EVM deposit watcher block was replaced", evidence)
        if recorded is not None:
            self.service.ledger.reorg_origin(*recorded)
        # A staged range may have partially committed before the crash.
        # Recheck its tracked deliveries. Historical committed origins can be
        # rechecked individually during the bridge's deep-reorg review.
        with self._db() as conn:
            pending = conn.execute("SELECT event_id, reference FROM evm_deposit_watch_delivery_v1").fetchall()
        changed = {}
        for event_id, raw in pending:
            reference = ChainReference.parse(raw)
            if reference.height > head.height:
                continue
            if reference.height not in changed:
                changed[reference.height] = self._block(hex(reference.height)).hash
            if changed[reference.height] != reference.block_hash:
                self.service.ledger.reorg_origin(event_id, reference)
        raise DepositWatchReorg("finalized EVM deposit block changed; outbound bridge actions held")

    def _require_active(self, checkpoint, head):
        if checkpoint is None or checkpoint.hash is None:
            return
        if checkpoint.height > head.height:
            raise DepositEvidenceError("finalized head is behind the stored deposit watcher checkpoint")
        actual = self._block(hex(checkpoint.height))
        if actual.hash != checkpoint.hash:
            self._pause_for_replacement(checkpoint, actual, head)

    def recheck_recorded(self, event_id: bytes) -> bool:
        """Check one historical source occurrence and alert on proven replacement."""
        with self._lock():
            state = self.service.ledger.state(event_id)
            if state is None or state.lane != "mint" or state.origin is None or not state.origin_confirmed:
                raise ValueError("no finalized deposit observation to recheck")
            head = self._head()
            origin = state.origin
            if origin.height > head.height:
                raise DepositEvidenceError("finalized head is behind the recorded deposit")
            canonical = self._block(hex(origin.height))
            if canonical.hash == origin.block_hash:
                return True
            self._pause_for_replacement(
                _Block(origin.height, origin.block_hash), canonical, head, recorded=(event_id, origin),
            )

    def _discover(self, start, end):
        query = {
            "fromBlock": hex(start), "toBlock": hex(end), "address": _hex(self.scope.vault),
            "topics": [_hex(DEPOSIT_TOPIC)],
        }
        logs = self._rpc("eth_getLogs", query)
        if not isinstance(logs, list):
            raise DepositEvidenceError("malformed reserve log range")
        return logs

    def _deliveries(self, logs, start, end, nonce):
        unique = {}
        for item in logs:
            log = _object(item, "discovered reserve log")
            event = _log_identity(log)
            position = event.height, event.log_index
            if (not start <= event.height <= end or event.emitter != self.scope.vault
                    or not event.topics or event.topics[0] != DEPOSIT_TOPIC):
                raise DepositEvidenceError("discovered log does not match the reserve filter")
            old = unique.setdefault(position, event)
            if old != event:
                raise DepositEvidenceError("conflicting reserve log position in the scanned range")

        receipts = {}

        def receipt_rpc(method, *args):
            if method == "eth_getTransactionReceipt":
                txid, = args
                if txid not in receipts:
                    receipts[txid] = self._rpc(method, *args)
                return receipts[txid]
            return self._rpc(method, *args)

        result = []
        for position in sorted(unique):
            event = unique[position]
            receipt = _object(receipt_rpc("eth_getTransactionReceipt", _hex(event.txid)), "discovered receipt")
            logs = receipt.get("logs")
            if not isinstance(logs, list):
                raise DepositEvidenceError("missing logs in discovered receipt")
            ordinals = [i for i, item in enumerate(logs)
                        if _quantity(_object(item, "receipt log").get("logIndex"), "receipt log index") == event.log_index]
            if len(ordinals) != 1 or _log_identity(logs[ordinals[0]]) != event:
                raise DepositEvidenceError("discovered log does not match its exact receipt")
            evidence = read_finalized_deposit(receipt_rpc, self.scope, event.txid, ordinals[0])
            nonce += 1
            if (evidence.block_number, evidence.block_hash, evidence.vault_nonce) != (event.height, event.block_hash, nonce):
                raise DepositEvidenceError("finalized deposit receipt or vault nonce is out of sequence")
            position = DepositPosition(self.scope.chain_id, self.scope.reserve_domain, self.scope.vault,
                                       evidence.tx_hash, evidence.receipt_log_ordinal)
            deposit = Deposit(position, evidence.source_asset, self.scope.bsv_network, self.scope.asset_id,
                              evidence.quantity, evidence.fee, evidence.owner)
            result.append((deposit, ChainReference(event.txid, ordinals[0], event.block_hash, event.height)))
        return tuple(result)

    def scan_once(self) -> DepositScan:
        with self._lock():
            cursor, staged = self._progress()
            head = self._head()
            self._require_active(cursor, head)
            self._require_active(staged, head)
            start = cursor.height + 1
            if start > head.height:
                return DepositScan(None, cursor.height, head.height, ())
            self._check_scope(head)
            if cursor.hash is None and cursor.height >= 0:
                baseline = self._block(hex(cursor.height))
                if self._nonce(baseline, before_start=True) != 0:
                    raise DepositEvidenceError("watcher start height is after an existing reserve deposit")
                self._checkpoint(baseline, 0)
                cursor = _Cursor(baseline.height, baseline.hash, 0)

            limit = staged.height if staged else min(head.height, start + self.max_blocks - 1)
            end = self._block(hex(limit))
            logs = self._discover(start, limit)
            while not staged and len(logs) > self.max_events and limit > start:
                limit = start + (limit - start) // 2
                end = self._block(hex(limit))
                logs = self._discover(start, limit)
            if len(logs) > self.max_events:
                raise DepositEvidenceError("reserve range exceeds watcher event limit")

            deliveries = self._deliveries(logs, start, limit, cursor.nonce)
            nonce = self._nonce(end)
            if nonce != cursor.nonce + len(deliveries) or (staged and nonce != staged.nonce):
                raise DepositEvidenceError("reserve nonce indicates incomplete finalized log discovery")
            current = self._head()
            for checkpoint in (cursor, staged, head, end):
                self._require_active(checkpoint, current)
            self._stage(end, nonce, deliveries, recovering=staged is not None)
            event_ids = []
            for deposit, reference in deliveries:
                event_id = self.service.ledger.observe_deposit(deposit, reference, finalized=True)
                state = self.service.ledger.state(event_id)
                if state is None or state.origin != reference or not state.origin_confirmed:
                    raise DepositEvidenceError("finalized deposit did not persist as the exact journal origin")
                event_ids.append(event_id)
            current = self._head()
            for checkpoint in (cursor, head, end):
                self._require_active(checkpoint, current)
            self._checkpoint(end, nonce, finish=True)
            return DepositScan(start, limit, current.height, tuple(event_ids))


def _log_identity(log):
    if log.get("removed", False) is not False:
        raise DepositEvidenceError("reserve log is marked removed")
    topics = log.get("topics")
    data = log.get("data")
    if not isinstance(topics, list) or type(data) is not str:
        raise DepositEvidenceError("malformed discovered log payload")
    return _DiscoveredLog(
        _quantity(log.get("blockNumber"), "discovered block height"),
        _quantity(log.get("logIndex"), "discovered block log index"),
        _data(log.get("blockHash"), 32, "discovered block hash"),
        _data(log.get("transactionHash"), 32, "discovered transaction hash"),
        _quantity(log.get("transactionIndex"), "discovered transaction index"),
        _data(log.get("address"), 20, "discovered emitter"),
        tuple(_data(topic, 32, "discovered topic") for topic in topics),
        _data(data, 256, "discovered deposit data"),
    )

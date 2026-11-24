"""Durable accounting of independently authenticated bridge observations.

A caller validates consensus, finality, and receipt contents before recording
them. This module neither signs nor submits a cross-chain operation. Persist
an authorization before handing the exact digest to any external signer.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import os
import sqlite3
import stat

from burn_receipt import BurnReceipt
from mint_events import Deposit, compressed_key
from projects.cctp.evm.bsv_burn_evidence import BurnReference
from projects.cctp.evm.release_adapter import burn_event_id
from shared.transaction import Transaction, hash256
from statement import AssetDescriptor, fixed, uint

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_scope (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1), descriptor BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS bridge_events (
    event_id BLOB PRIMARY KEY, lane TEXT NOT NULL CHECK (lane IN ('mint', 'release')),
    origin_data BLOB, origin_ref BLOB, origin_phase INTEGER NOT NULL DEFAULT 0,
    authorization BLOB, effect_data BLOB, effect_ref BLOB, effect_phase INTEGER NOT NULL DEFAULT 0,
    refund_ref BLOB
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_effect_position
ON bridge_events(lane, substr(effect_ref, 1, 36)) WHERE effect_phase > 0;
CREATE UNIQUE INDEX IF NOT EXISTS unique_authorization
ON bridge_events(authorization) WHERE authorization IS NOT NULL;
CREATE TABLE IF NOT EXISTS authorization_signatures (
    event_id BLOB PRIMARY KEY, digest BLOB NOT NULL, signature BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS mint_state_authorizations (
    state_outpoint BLOB PRIMARY KEY,
    event_id BLOB NOT NULL UNIQUE,
    digest BLOB NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS mint_authorization_drafts (
    event_id BLOB PRIMARY KEY, unsigned_transaction BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_refund_position
ON bridge_events(substr(refund_ref, 1, 36)) WHERE refund_ref IS NOT NULL;
CREATE TABLE IF NOT EXISTS ledger_audit (
    sequence INTEGER PRIMARY KEY, event_id BLOB, operation TEXT NOT NULL, detail BLOB
);
CREATE TABLE IF NOT EXISTS orphaned_evidence (
    event_id BLOB NOT NULL, stage TEXT NOT NULL, reference BLOB NOT NULL,
    PRIMARY KEY(event_id, stage, reference)
);
CREATE TABLE IF NOT EXISTS ledger_holds (
    hold_id INTEGER PRIMARY KEY, event_id BLOB, reason TEXT NOT NULL,
    resolved_by BLOB
);
CREATE TABLE IF NOT EXISTS reserve_entries (
    reference BLOB PRIMARY KEY, kind TEXT NOT NULL, quantity BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS unique_reserve_position
ON reserve_entries(substr(reference, 1, 36));
"""

_OBSERVED, _FINAL = 1, 2
_HOLD_ERRORS = ("origin reorganized after external authorization",
                "finalized cross-chain effect reorganized")


@dataclass(frozen=True)
class ChainReference:
    """Stable chain-native txid/vout or log ordinal, with its block occurrence."""

    txid: bytes
    position: int
    block_hash: bytes
    height: int

    def encode(self) -> bytes:
        fixed(self.txid, 32)
        fixed(self.block_hash, 32)
        if not any(self.txid) or not any(self.block_hash):
            raise ValueError("transaction and block references must be nonzero")
        return self.txid + uint(self.position, 4) + self.block_hash + uint(self.height, 4)

    @classmethod
    def parse(cls, raw: bytes | None) -> "ChainReference | None":
        if raw is None:
            return None
        fixed(raw, 72)
        return cls(raw[:32], int.from_bytes(raw[32:36], "little"), raw[36:68],
                   int.from_bytes(raw[68:72], "little"))


@dataclass(frozen=True)
class EventState:
    event_id: bytes
    lane: str
    phase: str
    origin: ChainReference | None
    effect: ChainReference | None
    authorization: bytes | None
    refund: ChainReference | None
    origin_confirmed: bool
    effect_confirmed: bool


@dataclass(frozen=True)
class MintAuthorizationDraft:
    deposit: Deposit
    transaction: Transaction
    state_outpoint: bytes
    digest: bytes


@dataclass(frozen=True)
class LedgerTotals:
    expected_source_balance: int
    expected_live_supply: int
    pending_mint: int
    pending_release: int
    finalized_deposits: int
    minted: int
    burned: int
    released: int
    mint_fees_retained: int
    release_fees_paid: int
    refunded: int
    net_reserve_provision: int
    unresolved_effects: int


@dataclass(frozen=True)
class Reconciliation:
    totals: LedgerTotals
    source_balance: int
    live_supply: int
    frozen_supply: int
    source_difference: int
    supply_difference: int
    backing_difference: int
    holds: tuple[tuple[int, str], ...]

    @property
    def balanced(self) -> bool:
        return (self.source_difference == self.supply_difference == self.backing_difference == 0
                and self.totals.unresolved_effects == 0 and self.totals.mint_fees_retained >= 0
                and self.totals.net_reserve_provision >= 0)

    @property
    def may_authorize(self) -> bool:
        return self.balanced and not self.holds


def _measure(quantity: int, fee: int, recipient: bytes) -> bytes:
    gross, paid_fee = uint(quantity, 8), uint(fee, 8)
    if quantity <= fee:
        raise ValueError("expected positive net quantity")
    return gross + paid_fee + recipient


def _quantities(raw: bytes) -> tuple[int, int]:
    return int.from_bytes(raw[:8], "little"), int.from_bytes(raw[8:16], "little")


class BridgeLedger:
    def __init__(self, path, asset: AssetDescriptor, source_chain_id: int, reserve_contract: bytes):
        self.path = str(path)
        self.asset = asset
        self.source_chain_id = source_chain_id
        self.reserve_contract = fixed(reserve_contract, 20)
        if self.path in ("", ":memory:") or not source_chain_id or not any(self.reserve_contract):
            raise ValueError("ledger needs a durable path and concrete reserve scope")
        descriptor = asset.encode() + uint(source_chain_id, 8) + self.reserve_contract
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        with self._db() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT descriptor FROM ledger_scope WHERE singleton = 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO ledger_scope VALUES (1, ?)", (descriptor,))
            elif row["descriptor"] != descriptor:
                raise ValueError("ledger belongs to a different bridge asset or reserve")

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        con.row_factory = sqlite3.Row
        try:
            con.execute("BEGIN IMMEDIATE")
            yield con
            con.commit()
        except BaseException:
            con.rollback()
            raise
        finally:
            con.close()

    @staticmethod
    def _audit(conn, event_id, operation, detail=None):
        conn.execute("INSERT INTO ledger_audit(event_id, operation, detail) VALUES (?, ?, ?)",
                     (event_id, operation, detail))

    @staticmethod
    def _row(conn, event_id):
        return conn.execute("SELECT * FROM bridge_events WHERE event_id = ?", (event_id,)).fetchone()

    @staticmethod
    def _holds(conn):
        return tuple((r["hold_id"], r["reason"]) for r in conn.execute(
            "SELECT hold_id, reason FROM ledger_holds WHERE resolved_by IS NULL ORDER BY hold_id"
        ))

    def _hold(self, conn, event_id, reason):
        row = conn.execute(
            "SELECT 1 FROM ledger_holds WHERE event_id IS ? AND reason = ? AND resolved_by IS NULL",
            (event_id, reason),
        ).fetchone()
        if row is None:
            conn.execute("INSERT INTO ledger_holds(event_id, reason) VALUES (?, ?)", (event_id, reason))
            self._audit(conn, event_id, "hold", reason.encode())

    def _record(self, event_id, lane, stage, reference, data, finalized) -> None:
        fixed(event_id, 32)
        if type(finalized) is not bool:
            raise ValueError("confirmation flag must be boolean")
        if stage not in ("origin", "effect"):
            raise ValueError("invalid bridge stage")
        raw_ref, phase = reference.encode(), _FINAL if finalized else _OBSERVED
        conflict = None
        with self._db() as conn:
            prior = self._row(conn, event_id)
            if prior is not None and prior["lane"] != lane:
                raise ValueError("bridge event lane does not match")
            if conn.execute(
                "SELECT 1 FROM orphaned_evidence WHERE event_id = ? AND stage = ? AND reference = ?",
                (event_id, stage, raw_ref),
            ).fetchone():
                self._audit(conn, event_id, stage + "_stale_replay", raw_ref)
                return
            if prior is not None and prior[stage + "_data"] not in (None, data):
                conflict = "contradictory canonical " + stage + " payload"
            elif (prior is not None and prior[stage + "_phase"] != 0
                  and prior[stage + "_ref"] != raw_ref):
                conflict = stage + " reference changed without a reorg observation"
            if conflict:
                self._audit(conn, event_id, stage + "_conflict", raw_ref + data)
                self._hold(conn, event_id, conflict)
            else:
                previous_phase = prior[stage + "_phase"] if prior is not None else 0
                if previous_phase >= phase:
                    self._audit(conn, event_id, stage + "_replay", raw_ref)
                    return
                conn.execute("INSERT OR IGNORE INTO bridge_events(event_id, lane) VALUES (?, ?)", (event_id, lane))
                try:
                    conn.execute(
                        f"UPDATE bridge_events SET {stage}_data = ?, {stage}_ref = ?, {stage}_phase = ? "
                        "WHERE event_id = ?", (data, raw_ref, phase, event_id),
                    )
                except sqlite3.IntegrityError as error:
                    raise ValueError("cross-chain effect already assigned to another bridge event") from error
                self._audit(conn, event_id, stage + ("_finalized" if finalized else "_observed"), raw_ref + data)
                row = self._row(conn, event_id)
                if row["origin_data"] is not None and row["effect_data"] is not None:
                    if self._expected_effect(row) != row["effect_data"] or row["refund_ref"] is not None:
                        conflict = "cross-chain effect does not settle its canonical origin"
                        self._hold(conn, event_id, conflict)
        if conflict:
            raise ValueError(conflict)

    def observe_deposit(self, deposit: Deposit, reference: ChainReference, *, finalized: bool) -> bytes:
        raw = deposit.encode()
        position = deposit.position
        if (position.source_chain_id != self.source_chain_id or position.reserve_contract != self.reserve_contract
                or position.reserve_domain != self.asset.reserve_domain or deposit.asset_id != self.asset.asset_id()
                or deposit.reserve_asset != self.asset.reserve_asset or deposit.destination_network != self.asset.network):
            raise ValueError("deposit is outside the ledger scope")
        if (position.transaction_hash, position.log_ordinal) != (reference.txid, reference.position):
            raise ValueError("deposit position does not match its chain reference")
        event_id = position.event_id()
        self._record(event_id, "mint", "origin", reference, raw, finalized)
        return event_id

    def observe_burn(self, burn: BurnReceipt, reference: ChainReference, *, finalized: bool) -> bytes:
        if burn.asset_id != self.asset.asset_id() or burn.reserve_domain != self.asset.reserve_domain:
            raise ValueError("burn is outside the ledger scope")
        burn.output()
        event_id = burn_event_id(self.asset.network, BurnReference(
            reference.txid, reference.position, reference.block_hash, reference.height,
        ))
        self._record(event_id, "release", "origin", reference, _measure(burn.quantity, burn.fee, burn.recipient),
                     finalized)
        return event_id

    def observe_mint(self, event_id, reference: ChainReference, quantity, owner, *, finalized: bool):
        self._record(event_id, "mint", "effect", reference, _measure(quantity, 0, compressed_key(owner)), finalized)

    def observe_release(self, event_id, reference: ChainReference, quantity, fee, recipient, *, finalized: bool):
        self._record(event_id, "release", "effect", reference, _measure(quantity, fee, fixed(recipient, 20)), finalized)

    @staticmethod
    def _expected_effect(row):
        if row["lane"] == "release":
            return row["origin_data"]
        deposit = Deposit.parse(row["origin_data"])
        return _measure(deposit.net_quantity, 0, deposit.owner)

    def authorize(self, event_id: bytes, digest: bytes) -> bool:
        """Acquire the one external release authorization attempt for an event.

        True grants new work. False means the same claim was already recorded.
        Mint authorization requires the actual state outpoint.
        """
        return self._authorize(event_id, digest, mint_state_outpoint=None, mint_draft=None)

    def authorize_mint(
        self, event_id: bytes, digest: bytes, state_outpoint: bytes, *, transaction: Transaction | None = None,
    ) -> bool:
        """Atomically bind one event and signing digest to a serial mint input."""
        fixed(state_outpoint, 36)
        if not any(state_outpoint[:32]) or state_outpoint[32:] != bytes(4):
            raise ValueError("mint authorization requires actual state vout zero")
        draft = None
        if transaction is not None:
            self._private_signature_cache()
            if (not transaction.inputs or transaction.inputs[0].script
                    or transaction.inputs[0].outpoint() != state_outpoint):
                raise ValueError("mint recovery draft disagrees with the unsigned state spend")
            draft = transaction.serialize()
        return self._authorize(event_id, digest, mint_state_outpoint=state_outpoint, mint_draft=draft)

    def _authorize(self, event_id, digest, mint_state_outpoint, mint_draft):
        fixed(event_id, 32)
        fixed(digest, 32)
        if not any(digest):
            raise ValueError("authorization digest must be nonzero")
        with self._db() as conn:
            row = self._row(conn, event_id)
            if row is None or row["origin_phase"] != _FINAL:
                raise ValueError("canonical origin has not finalized")
            if self._holds(conn):
                raise ValueError("outbound bridge actions are held for review")
            if row["lane"] == "mint" and mint_state_outpoint is None:
                raise ValueError("mint authorization must reserve its state outpoint")
            if mint_state_outpoint is not None:
                if row["lane"] != "mint":
                    raise ValueError("only a mint may reserve the mint state outpoint")
                self._reserve_mint_state(conn, row, mint_state_outpoint, event_id, digest)
                if mint_draft is not None:
                    existing = conn.execute(
                        "SELECT unsigned_transaction FROM mint_authorization_drafts WHERE event_id = ?", (event_id,),
                    ).fetchone()
                    if existing is None:
                        conn.execute("INSERT INTO mint_authorization_drafts VALUES (?, ?)", (event_id, mint_draft))
                    elif existing["unsigned_transaction"] != mint_draft:
                        raise ValueError("mint retry differs from the recorded transaction draft")
            if row["authorization"] is not None:
                if row["authorization"] != digest:
                    raise ValueError("a different authorization is already recorded for this event")
                self._audit(conn, event_id, "authorization_replay", digest)
                return False
            if row["effect_phase"] or row["refund_ref"] is not None:
                raise ValueError("event has already advanced beyond authorization")
            try:
                conn.execute("UPDATE bridge_events SET authorization = ? WHERE event_id = ?", (digest, event_id))
            except sqlite3.IntegrityError as error:
                raise ValueError("authorization digest belongs to another bridge event") from error
            self._audit(conn, event_id, "authorization_recorded", digest)
            return True

    def _reserve_mint_state(self, conn, row, outpoint, event_id, digest):
        reservation = conn.execute(
            "SELECT event_id, digest FROM mint_state_authorizations WHERE state_outpoint = ?", (outpoint,),
        ).fetchone()
        if reservation is not None:
            if reservation["event_id"] != event_id:
                raise ValueError("another mint already reserved this state outpoint")
            if reservation["digest"] != digest:
                raise ValueError("a different authorization is already recorded for this mint state")
            return
        previous = conn.execute(
            "SELECT state_outpoint FROM mint_state_authorizations WHERE event_id = ?", (event_id,),
        ).fetchone()
        if previous is not None:
            raise ValueError("this mint authorization is bound to a different state outpoint")
        if row["effect_phase"] or row["refund_ref"] is not None:
            raise ValueError("event has already advanced beyond authorization")
        if row["authorization"] is None and conn.execute(
            "SELECT 1 FROM bridge_events AS event "
            "LEFT JOIN mint_state_authorizations AS reservation ON reservation.event_id = event.event_id "
            "WHERE event.lane = 'mint' AND event.authorization IS NOT NULL AND event.effect_phase != ? "
            "AND reservation.state_outpoint IS NULL LIMIT 1", (_FINAL,),
        ).fetchone():
            # Older journals persisted an authorization digest without its
            # predecessor. Only an identical replay may bind that attempt.
            raise ValueError("unfinished legacy mint authorization has no bound state outpoint")
        try:
            conn.execute("INSERT INTO mint_state_authorizations VALUES (?, ?, ?)", (outpoint, event_id, digest))
        except sqlite3.IntegrityError as error:
            raise ValueError("mint authorization digest belongs to another state outpoint") from error
        self._audit(conn, event_id, "mint_state_reserved", outpoint + digest)

    def mint_authorization_draft(self, event_id: bytes) -> MintAuthorizationDraft:
        self._private_signature_cache()
        fixed(event_id, 32)
        with self._db() as conn:
            row = conn.execute(
                "SELECT origin_data, origin_phase, effect_phase, refund_ref, state_outpoint, digest, "
                "unsigned_transaction FROM bridge_events JOIN mint_state_authorizations USING (event_id) "
                "JOIN mint_authorization_drafts USING (event_id) WHERE event_id = ?", (event_id,),
            ).fetchone()
            if (row is None or row["origin_phase"] != _FINAL or row["effect_phase"] == _FINAL
                    or row["refund_ref"] is not None or self._holds(conn)):
                raise ValueError("no recoverable mint authorization draft")
            return MintAuthorizationDraft(Deposit.parse(row["origin_data"]), Transaction.parse(
                row["unsigned_transaction"]), row["state_outpoint"], row["digest"])

    def note_confirmed_mint_spend(self, state_outpoint: bytes, event_id: bytes, digest: bytes) -> None:
        """Hold for review if a verified mint disagrees with a pending authorization."""
        fixed(state_outpoint, 36)
        fixed(event_id, 32)
        fixed(digest, 32)
        with self._db() as conn:
            reservation = conn.execute(
                "SELECT event_id, digest FROM mint_state_authorizations WHERE state_outpoint = ?", (state_outpoint,),
            ).fetchone()
            row = self._row(conn, event_id)
            if reservation is not None and (reservation["event_id"], reservation["digest"]) != (event_id, digest):
                self._hold(conn, reservation["event_id"], "confirmed mint used a differently reserved state outpoint")
                self._audit(conn, reservation["event_id"], "mint_state_conflict", state_outpoint + event_id + digest)
            if row is not None and row["authorization"] not in (None, digest):
                self._hold(conn, event_id, "confirmed mint disagrees with recorded authorization")
                self._audit(conn, event_id, "mint_authorization_conflict", state_outpoint + digest)

    def _signed_row(self, conn, event_id, digest):
        fixed(event_id, 32)
        fixed(digest, 32)
        row = self._row(conn, event_id)
        if (row is None or row["authorization"] != digest or row["origin_phase"] != _FINAL
                or row["refund_ref"] or row["effect_phase"] == _FINAL or self._holds(conn)):
            raise ValueError("signing authorization is no longer available")
        return conn.execute(
            "SELECT signature FROM authorization_signatures WHERE event_id = ? AND digest = ?", (event_id, digest),
        ).fetchone()

    def authorization_signature(self, event_id: bytes, digest: bytes) -> bytes | None:
        self._private_signature_cache()
        with self._db() as conn:
            row = self._signed_row(conn, event_id, digest)
            return row["signature"] if row is not None else None

    def record_authorization_signature(self, event_id: bytes, digest: bytes, signature: bytes) -> bytes:
        """Cache a validated, scoped signature without putting it in audit output."""
        if type(signature) is not bytes or not 1 <= len(signature) <= 73:
            raise ValueError("invalid authorization signature encoding")
        self._private_signature_cache()
        with self._db() as conn:
            row = self._signed_row(conn, event_id, digest)
            if row is not None:
                return row["signature"]
            conn.execute("INSERT INTO authorization_signatures VALUES (?, ?, ?)", (event_id, digest, signature))
            self._audit(conn, event_id, "signature_recorded", digest)
            return signature

    def _private_signature_cache(self) -> None:
        mode = os.stat(self.path, follow_symlinks=False).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ValueError("authorization cache requires an owner-only ledger file")

    def hold(self, reason: str, evidence: bytes, *, event_id: bytes | None = None) -> None:
        """Record an operator or adapter hold without altering observed balances."""
        fixed(evidence, 32)
        if event_id is not None:
            fixed(event_id, 32)
        if not reason or not any(evidence):
            raise ValueError("hold requires a reason and evidence")
        with self._db() as conn:
            self._hold(conn, event_id, reason)
            self._audit(conn, event_id, "hold_evidence", evidence)

    def reorg_origin(self, event_id: bytes, reference: ChainReference) -> bool:
        return self._reorg(event_id, "origin", reference)

    def reorg_effect(self, event_id: bytes, reference: ChainReference) -> bool:
        return self._reorg(event_id, "effect", reference)

    def _reorg(self, event_id, stage, reference):
        fixed(event_id, 32)
        raw_ref = reference.encode()
        with self._db() as conn:
            row = self._row(conn, event_id)
            if (row is None or row[stage + "_ref"] != raw_ref or row[stage + "_phase"] == 0):
                return False
            conn.execute(
                "INSERT OR IGNORE INTO orphaned_evidence(event_id, stage, reference) VALUES (?, ?, ?)",
                (event_id, stage, raw_ref),
            )
            conn.execute(f"UPDATE bridge_events SET {stage}_phase = 0 WHERE event_id = ?", (event_id,))
            self._audit(conn, event_id, stage + "_orphaned", raw_ref)
            if stage == "origin" and (row["authorization"] or row["effect_phase"] or row["refund_ref"]):
                self._hold(conn, event_id, _HOLD_ERRORS[0])
            if stage == "effect" and row["effect_phase"] == _FINAL:
                self._hold(conn, event_id, _HOLD_ERRORS[1])
            return True

    def observe_refund(self, event_id: bytes, reference: ChainReference, quantity: int) -> None:
        """Record a finalized full reserve refund before the deposit was authorized."""
        fixed(event_id, 32)
        uint(quantity, 8)
        raw_ref = reference.encode()
        with self._db() as conn:
            if conn.execute(
                "SELECT 1 FROM orphaned_evidence WHERE event_id = ? AND stage = 'refund' AND reference = ?",
                (event_id, raw_ref),
            ).fetchone():
                return
            row = self._row(conn, event_id)
            if (row is None or row["lane"] != "mint" or row["origin_phase"] != _FINAL
                    or row["authorization"] or row["effect_phase"]):
                raise ValueError("refund requires a finalized deposit with no external mint action")
            if quantity != Deposit.parse(row["origin_data"]).gross_quantity:
                raise ValueError("refund quantity differs from the deposit")
            if row["refund_ref"] == raw_ref:
                return
            if row["refund_ref"] is not None:
                raise ValueError("deposit already has a refund")
            conn.execute("UPDATE bridge_events SET refund_ref = ? WHERE event_id = ?", (raw_ref, event_id))
            self._audit(conn, event_id, "refund_finalized", raw_ref)

    def reorg_refund(self, event_id: bytes, reference: ChainReference) -> bool:
        fixed(event_id, 32)
        raw_ref = reference.encode()
        with self._db() as conn:
            row = self._row(conn, event_id)
            if row is None or row["refund_ref"] != raw_ref:
                return False
            conn.execute("UPDATE bridge_events SET refund_ref = NULL WHERE event_id = ?", (event_id,))
            conn.execute("INSERT INTO orphaned_evidence VALUES (?, 'refund', ?)", (event_id, raw_ref))
            self._audit(conn, event_id, "refund_orphaned", raw_ref)
            self._hold(conn, event_id, "finalized refund reorganized")
            return True

    def observe_reserve_entry(self, reference: ChainReference, kind: str, quantity: int) -> None:
        """Book a verified reserve-side provision, withdrawal, or fee transfer."""
        if kind not in ("provision", "return_provision", "fee_sweep") or not quantity:
            raise ValueError("invalid reserve adjustment kind or quantity")
        encoded, raw_ref = uint(quantity, 8), reference.encode()
        entry_id = hash256(b"BSV/CCTP/reserve-entry/v1\0" + raw_ref[:36])
        with self._db() as conn:
            if conn.execute(
                "SELECT 1 FROM orphaned_evidence WHERE event_id = ? AND stage = 'reserve_entry' AND reference = ?",
                (entry_id, raw_ref),
            ).fetchone():
                return
            existing = conn.execute("SELECT * FROM reserve_entries WHERE reference = ?", (raw_ref,)).fetchone()
            if existing is not None:
                if (existing["kind"], existing["quantity"]) != (kind, encoded):
                    raise ValueError("reserve adjustment already recorded with other terms")
                return
            conn.execute("INSERT INTO reserve_entries VALUES (?, ?, ?)", (raw_ref, kind, encoded))
            self._audit(conn, entry_id, kind, raw_ref + encoded)

    def reorg_reserve_entry(self, reference: ChainReference) -> bool:
        raw_ref = reference.encode()
        entry_id = hash256(b"BSV/CCTP/reserve-entry/v1\0" + raw_ref[:36])
        with self._db() as conn:
            cursor = conn.execute("DELETE FROM reserve_entries WHERE reference = ?", (raw_ref,))
            if cursor.rowcount == 0:
                return False
            conn.execute("INSERT INTO orphaned_evidence VALUES (?, 'reserve_entry', ?)", (entry_id, raw_ref))
            self._audit(conn, entry_id, "reserve_entry_orphaned", raw_ref)
            self._hold(conn, entry_id, "finalized reserve adjustment reorganized")
            return True

    def state(self, event_id: bytes) -> EventState | None:
        fixed(event_id, 32)
        with self._db() as conn:
            row = self._row(conn, event_id)
            if row is None:
                return None
            origin, effect = row["origin_phase"], row["effect_phase"]
            held = conn.execute(
                "SELECT 1 FROM ledger_holds WHERE event_id = ? AND resolved_by IS NULL", (event_id,),
            ).fetchone()
            if held:
                phase = "held"
            elif row["refund_ref"]:
                phase = "refunded"
            elif origin != _FINAL and effect:
                phase = "waiting_for_origin"
            elif effect == _FINAL:
                phase = "settled"
            elif effect:
                phase = "submitted"
            elif origin == 0:
                phase = "orphaned"
            elif row["authorization"]:
                phase = "authorized"
            else:
                phase = "finalized" if origin == _FINAL else "observed"
            return EventState(event_id, row["lane"], phase, ChainReference.parse(row["origin_ref"] if origin else None),
                              ChainReference.parse(row["effect_ref"] if effect else None), row["authorization"],
                              ChainReference.parse(row["refund_ref"]), origin == _FINAL, effect == _FINAL)

    def _totals(self, conn) -> LedgerTotals:
        deposits = mint_fees = minted = burns = released = release_fees = refunded = 0
        pending_mint = pending_release = unresolved = 0
        for row in conn.execute("SELECT * FROM bridge_events"):
            origin_final = row["origin_phase"] == _FINAL
            effect_final = row["effect_phase"] == _FINAL
            match = (row["origin_data"] is not None and row["effect_data"] is not None
                     and self._expected_effect(row) == row["effect_data"] and not row["refund_ref"])
            if effect_final and (not match or not origin_final):
                unresolved += 1
            if row["lane"] == "mint":
                if origin_final:
                    deposit = Deposit.parse(row["origin_data"])
                    deposits += deposit.gross_quantity
                    if row["refund_ref"]:
                        refunded += deposit.gross_quantity
                    else:
                        mint_fees += deposit.fee_quantity
                        if not (effect_final and match):
                            pending_mint += deposit.net_quantity
                if effect_final:
                    minted += _quantities(row["effect_data"])[0]
            else:
                if origin_final:
                    gross, _ = _quantities(row["origin_data"])
                    burns += gross
                    if not (effect_final and match):
                        pending_release += gross
                if effect_final:
                    gross, fee = _quantities(row["effect_data"])
                    released += gross
                    release_fees += fee
        provision = sweep = 0
        for row in conn.execute("SELECT kind, quantity FROM reserve_entries"):
            quantity = int.from_bytes(row["quantity"], "little")
            if row["kind"] == "fee_sweep":
                sweep += quantity
            else:
                provision += quantity if row["kind"] == "provision" else -quantity
        return LedgerTotals(deposits - released - refunded + provision - sweep, minted - burns,
                            pending_mint, pending_release, deposits, minted, burns, released,
                            mint_fees - sweep, release_fees, refunded, provision, unresolved)

    def totals(self) -> LedgerTotals:
        with self._db() as conn:
            return self._totals(conn)

    def _compare(self, conn, source_balance, live_supply, frozen_supply):
        if (any(type(value) is not int or value < 0 for value in (source_balance, live_supply, frozen_supply))
                or frozen_supply > live_supply):
            raise ValueError("invalid observed reserve, live supply, or frozen supply")
        totals = self._totals(conn)
        source_delta = source_balance - totals.expected_source_balance
        supply_delta = live_supply - totals.expected_live_supply
        adjusted_backing = source_balance - totals.mint_fees_retained - totals.net_reserve_provision
        backing_delta = adjusted_backing - live_supply - totals.pending_mint - totals.pending_release
        return Reconciliation(totals, source_balance, live_supply, frozen_supply, source_delta, supply_delta,
                              backing_delta, self._holds(conn))

    def reconcile(self, *, source_balance: int, live_supply: int, frozen_supply: int) -> Reconciliation:
        """Compare independent chain-side balances and persist a hold on any mismatch."""
        with self._db() as conn:
            result = self._compare(conn, source_balance, live_supply, frozen_supply)
            if not result.balanced:
                self._hold(conn, None, "independent reserve and supply reconciliation disagrees")
                result = self._compare(conn, source_balance, live_supply, frozen_supply)
            return result

    def resolve_hold(
        self, hold_id: int, review_evidence: bytes, *, source_balance: int, live_supply: int, frozen_supply: int,
    ) -> bool:
        """Record an authorized operator's review against recovered independent balances."""
        uint(hold_id, 8)
        fixed(review_evidence, 32)
        if not 0 < hold_id < 2**63 or not any(review_evidence):
            raise ValueError("missing hold ID or review evidence")
        with self._db() as conn:
            result = self._compare(conn, source_balance, live_supply, frozen_supply)
            if not result.balanced:
                raise ValueError("reconciliation must balance before a hold can be resolved")
            row = conn.execute("SELECT * FROM ledger_holds WHERE hold_id = ?", (hold_id,)).fetchone()
            if row is None:
                raise ValueError("unknown bridge hold")
            if row["resolved_by"] is not None:
                if row["resolved_by"] != review_evidence:
                    raise ValueError("hold was already resolved against other evidence")
                return False
            conn.execute("UPDATE ledger_holds SET resolved_by = ? WHERE hold_id = ?", (review_evidence, hold_id))
            self._audit(conn, row["event_id"], "hold_resolved", uint(hold_id, 8) + review_evidence)
            return True

    def audit_log(self, after: int = 0) -> tuple[tuple[int, bytes | None, str, bytes | None], ...]:
        if type(after) is not int or not 0 <= after < 2**63:
            raise ValueError("invalid audit cursor")
        with self._db() as conn:
            return tuple(tuple(row) for row in conn.execute(
                "SELECT sequence, event_id, operation, detail FROM ledger_audit "
                "WHERE sequence > ? ORDER BY sequence", (after,),
            ))

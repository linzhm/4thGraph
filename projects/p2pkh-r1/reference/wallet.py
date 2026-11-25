"""Checked wallet entry point for P2PKH-R1. Only the supplied signer holds a private key."""
from contextlib import closing
from hashlib import new, sha256
import sqlite3

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from tx_engine import Script, Tx, TxIn

from p2pkh_r1 import recognize
from signature import GROUP_ORDER_R1, UNIVERSAL_FLAGS, authorization, current_input_unlock


class SigningKeyBlocked(RuntimeError):
    """The wallet observed a repeated r on different signed digests for this key."""


def _ensure_active(db, pubkey):
    if db.execute("SELECT 1 FROM blocked_keys WHERE pubkey=?", (pubkey,)).fetchone():
        raise SigningKeyBlocked("P-256 key blocked after a nonce-reuse warning")


def sign_spend(tx, index, parent, requested_type, pubkey, sign_digest, history_path, *, compress_otda=False):
    """Validate the parent and policy; call sign_digest(bytes32) -> raw r||s once.

    The caller verifies the required funding confirmation in its chain view.
    Use one persistent history per wallet across restarts and signing processes.
    The callback must keep its output private until this function returns.
    Set compress_otda only when Chronicle functional unlocking is available.
    """
    if not 0 <= index < len(tx.tx_ins):
        raise ValueError("input index out of range")
    txin = tx.tx_ins[index]
    if txin.prev_tx.lower() != parent.id().lower() or not 0 <= txin.prev_index < len(parent.tx_outs):
        raise ValueError("parent outpoint mismatch")
    output = parent.tx_outs[txin.prev_index]
    owner = recognize(output.script_pubkey.raw_serialize())
    if owner is None or requested_type not in UNIVERSAL_FLAGS:
        raise ValueError("unrecognized template or sighash type")
    if len(pubkey) != 65 or pubkey[0] != 4:
        raise ValueError("expected uncompressed X9.63 P-256 key")
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
    if new("ripemd160", sha256(pubkey).digest()).digest() != owner:
        raise ValueError("owner key mismatch")
    auth = authorization(tx, index, output.amount, requested_type)
    digest = auth.digest()

    with closing(sqlite3.connect(history_path, timeout=30)) as db:
        db.execute("CREATE TABLE IF NOT EXISTS seen_r "
                   "(pubkey BLOB NOT NULL, r BLOB NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(pubkey,r))")
        db.execute("CREATE TABLE IF NOT EXISTS blocked_keys (pubkey BLOB PRIMARY KEY)")
        _ensure_active(db, pubkey)
        signature = sign_digest(digest)
        if len(signature) != 64:
            raise ValueError("expected fixed-width r || s")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        if not (0 < r < GROUP_ORDER_R1 and 0 < s < GROUP_ORDER_R1):
            raise ValueError("P-256 signature scalar out of range")
        key.verify(utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        # Serialize the compare-and-record decision, including across processes.
        with db:
            db.execute("BEGIN IMMEDIATE")
            _ensure_active(db, pubkey)
            row = db.execute("SELECT digest FROM seen_r WHERE pubkey=? AND r=?", (pubkey, signature[:32])).fetchone()
            conflict = row is not None and row[0] != digest
            if conflict:
                db.execute("INSERT INTO blocked_keys VALUES (?)", (pubkey,))
            elif row is None:
                db.execute("INSERT INTO seen_r VALUES (?,?,?)", (pubkey, signature[:32], digest))
        if conflict:
            raise SigningKeyBlocked("same P-256 r observed on different digests; signature withheld")
    return current_input_unlock(auth, pubkey, signature, compress_otda_for=tx if compress_otda else None)


def sign_payment(parent, vout, outputs, fee_sats, pubkey, sign_digest, history_path):
    """Finish an ordinary single-input payment using BIP143 ALL (0x41).

    Supply the intended TxOut list, including any change, and the approved fee.
    For mixed inputs or another sighash use sign_spend on the prepared transaction.
    """
    if not 0 <= vout < len(parent.tx_outs):
        raise ValueError("parent output index out of range")
    outputs = list(outputs)
    if not outputs or any(output.amount < 0 for output in outputs):
        raise ValueError("expected payment outputs with nonnegative amounts")
    if fee_sats < 0 or parent.tx_outs[vout].amount != sum(output.amount for output in outputs) + fee_sats:
        raise ValueError("payment outputs and approved fee do not balance")
    unsigned = Tx(2, [TxIn(parent.id(), vout, Script())], outputs, 0)
    unlock = sign_spend(unsigned, 0, parent, 0x41, pubkey, sign_digest, history_path)
    prev = unsigned.tx_ins[0]
    signed = Tx(unsigned.version, [TxIn(prev.prev_tx, prev.prev_index, unlock, prev.sequence)],
                unsigned.tx_outs, unsigned.locktime)
    signed.validate([parent])
    return signed

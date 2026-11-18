"""Checked wallet entry point for v7. Only the supplied signer holds a private key."""
from contextlib import closing
from hashlib import new, sha256
import sqlite3

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from handwritten import GROUP_ORDER_R1, match_locking_script
from universal import authorization, universal_unlocking_script


class SigningKeyBlocked(RuntimeError):
    """The wallet observed a repeated r on different signed digests for this key."""


def _ensure_active(db, pubkey):
    if db.execute("SELECT 1 FROM blocked_keys WHERE pubkey=?", (pubkey,)).fetchone():
        raise SigningKeyBlocked("P-256 key blocked after a nonce-reuse warning")


def sign_spend(tx, index, parent, requested_type, pubkey, sign_digest, history_path):
    """Validate the parent and policy; call sign_digest(bytes32) -> raw r||s once.

    Use one persistent history per wallet across restarts and signing processes.
    The callback must keep its output private until this function returns.
    """
    if not 0 <= index < len(tx.tx_ins):
        raise ValueError("input index out of range")
    txin = tx.tx_ins[index]
    if txin.prev_tx.lower() != parent.id().lower() or not 0 <= txin.prev_index < len(parent.tx_outs):
        raise ValueError("parent outpoint mismatch")
    output = parent.tx_outs[txin.prev_index]
    lock = match_locking_script(output.script_pubkey.raw_serialize())
    if lock is None or lock.version != 7 or requested_type not in lock.allowed_types:
        raise ValueError("unrecognized template or disallowed sighash")
    if len(pubkey) != 65 or pubkey[0] != 4:
        raise ValueError("expected uncompressed X9.63 P-256 key")
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
    if new("ripemd160", sha256(pubkey).digest()).digest() != lock.owner_hash160:
        raise ValueError("owner key mismatch")
    auth = authorization(tx, index, output.amount, requested_type)
    digest = auth.digest()
    parent_bytes = parent.serialize()

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
    return universal_unlocking_script(parent_bytes, auth, pubkey, signature)

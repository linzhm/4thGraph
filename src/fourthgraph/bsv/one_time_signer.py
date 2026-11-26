"""Reserve a one-time test or wallet key durably before calling its signer."""
from collections.abc import Callable
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3


class KeyAlreadyUsed(ValueError):
    """The wallet has already authorized use of this one-time key."""


def durable_signer(
    database: Path, algorithm: str, public_key: bytes, sign: Callable[[bytes], bytes],
) -> Callable[[bytes], bytes]:
    """Wrap a signer with a SQLite consumption record shared across processes.

    Use the same database and canonical public key for every format in an
    algorithm. Preserve this database across wallet restarts. Restoring a
    stale database requires retiring all keys with uncertain use.
    """
    key_id = sha256(algorithm.encode("ascii") + b"\0" + public_key).digest()

    def sign_once(digest):
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise ValueError("expected a 32-byte digest")
        with closing(sqlite3.connect(database, timeout=30)) as db:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                db.execute("CREATE TABLE IF NOT EXISTS used_keys (key_id BLOB PRIMARY KEY)")
                inserted = db.execute(
                    "INSERT INTO used_keys VALUES (?) ON CONFLICT DO NOTHING", (key_id,),
                )
                if inserted.rowcount != 1:
                    raise KeyAlreadyUsed("one-time key already consumed")
        # A signer failure can follow disclosure in another process. Keep the
        # durable reservation even when the callback fails.
        return sign(digest)

    return sign_once

from hashlib import shake_256

from lamport import KEY_BYTES, public_key, sign_digest
from script import compact_forth_committed_locking_script


def cases():
    for seed, profile, length, sighash in (
        (b"sdk Lamport full-key fixture", "full-key", 22780, 0x41),
        (b"sdk Lamport committed fixture", "committed-key", 7746, 0x61),
        (b"sdk Lamport Forth committed fixture", "committed-key-forth", 7042, 0x41),
        (b"sdk Lamport compact Forth fixture", "committed-key-forth-compact", 6830, 0x61),
    ):
        secret = shake_256(seed).digest(KEY_BYTES)
        yield dict(public_key=public_key(secret), signer=lambda digest: sign_digest(secret, digest),
                   profile=profile, bytes=length, sighash=sighash)
    secret = shake_256(b"sdk Lamport reconstructed input").digest(KEY_BYTES)
    destination_key = public_key(shake_256(b"sdk Lamport reconstructed output").digest(KEY_BYTES))
    yield dict(public_key=public_key(secret), signer=lambda digest: sign_digest(secret, digest),
               profile="committed-key-forth-compact", bytes=6830, sighash=0xe1, compress_otda=True,
               reconstructed=True, destination=compact_forth_committed_locking_script(destination_key))

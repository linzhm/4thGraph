from functools import partial
from hashlib import shake_256

import subset
from lamport import KEY_BYTES, public_key, sign_digest
from script import compact_forth_committed_locking_script, subset_locking_script, v020_forth_committed_locking_script


def cases():
    for seed, profile, length, sighash in (
        (b"sdk Lamport full-key fixture", "full-key", 22780, 0x41),
        (b"sdk Lamport committed fixture", "committed-key", 7746, 0x61),
        (b"sdk Lamport Forth committed fixture", "committed-key-forth", 7042, 0x41),
        (b"sdk Lamport compact Forth fixture", "committed-key-forth-compact", 6830, 0x61),
        (b"sdk Lamport v0.2.0 fixture", "committed-key-forth-v0.2.0", 6525, 0x41),
    ):
        secret = shake_256(seed).digest(KEY_BYTES)
        yield dict(public_key=public_key(secret), signer=partial(sign_digest, secret),
                   profile=profile, bytes=length, sighash=sighash)
    secret = shake_256(b"sdk Lamport reconstructed input").digest(KEY_BYTES)
    destination_key = public_key(shake_256(b"sdk Lamport reconstructed output").digest(KEY_BYTES))
    yield dict(public_key=public_key(secret), signer=partial(sign_digest, secret),
               profile="committed-key-forth-compact", bytes=6830, sighash=0xe1, compress_otda=True,
               reconstructed=True, destination=compact_forth_committed_locking_script(destination_key))
    secret = shake_256(b"sdk Lamport v0.2.0 reconstructed input").digest(KEY_BYTES)
    destination_key = public_key(shake_256(b"sdk Lamport v0.2.0 reconstructed output").digest(KEY_BYTES))
    yield dict(public_key=public_key(secret), signer=partial(sign_digest, secret),
               profile="committed-key-forth-v0.2.0", bytes=6525, sighash=0x61, compress_otda=True,
               reconstructed=True, destination=v020_forth_committed_locking_script(destination_key))
    secret = shake_256(b"sdk Lamport fixed-weight exit").digest(subset.KEY_BYTES)
    yield dict(public_key=subset.public_key(secret), signer=partial(subset.sign_digest, secret),
               profile=subset.PROFILE, bytes=8003, sighash=0x41, algorithm=subset.ALGORITHM)
    secret = shake_256(b"sdk Lamport fixed-weight turnover").digest(subset.KEY_BYTES)
    destination_key = subset.public_key(shake_256(b"sdk Lamport fixed-weight destination").digest(subset.KEY_BYTES))
    yield dict(public_key=subset.public_key(secret), signer=partial(subset.sign_digest, secret),
               profile=subset.PROFILE, bytes=8003, sighash=0x61, algorithm=subset.ALGORITHM, compress_otda=True,
               reconstructed=True, destination=subset_locking_script(destination_key))

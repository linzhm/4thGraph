from hashlib import shake_256

from lamport import KEY_BYTES, public_key, sign_digest


def cases():
    for seed, profile, length, sighash in (
        (b"sdk Lamport full-key fixture", "full-key", 22780, 0x41),
        (b"sdk Lamport committed fixture", "committed-key", 7746, 0x61),
        (b"sdk Lamport Forth committed fixture", "committed-key-forth", 7042, 0x41),
    ):
        secret = shake_256(seed).digest(KEY_BYTES)
        yield dict(public_key=public_key(secret), signer=lambda digest: sign_digest(secret, digest),
                   profile=profile, bytes=length, sighash=sighash)

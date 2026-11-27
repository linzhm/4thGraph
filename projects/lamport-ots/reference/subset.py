"""Lamport's independent SHA-256 commitments with an injective fixed-weight code."""
from hashlib import sha256
from hmac import compare_digest
from secrets import token_bytes

import lamport

ALGORITHM = 'lamport-ots-subset'
PROFILE = 'committed-key-forth-subset'
SLOTS = 11
WEIGHT = 4
KEY_BYTES = 32 * SLOTS * 32
SIGNATURE_BYTES = 32 * WEIGHT * 32
MASKS = tuple(mask for mask in range(1 << SLOTS) if mask.bit_count() == WEIGHT)[:256]
MASK_TABLE = b''.join(mask.to_bytes(2, 'little') for mask in MASKS)


def is_subset_key(key):
    return isinstance(key, bytes) and len(key) == KEY_BYTES


def _selected(digest):
    lamport.require_bytes(digest, 32, 'digest')
    return (group * SLOTS + slot for group, byte in enumerate(digest)
            for slot in range(SLOTS) if MASKS[byte] & (1 << slot))


def _slot(data, index):
    return data[32 * index:32 * (index + 1)]


def public_key(secret):
    lamport.require_bytes(secret, KEY_BYTES, 'subset secret key')
    return b''.join(sha256(_slot(secret, i)).digest() for i in range(KEY_BYTES // 32))


def generate_keypair():
    secret = token_bytes(KEY_BYTES)
    return secret, public_key(secret)


def sign_digest(secret, digest):
    """Low-level primitive. A signer must durably consume the key before disclosure."""
    lamport.require_bytes(secret, KEY_BYTES, 'subset secret key')
    return b''.join(_slot(secret, i) for i in _selected(digest))


def verify_digest(key, digest, signature):
    try:
        lamport.require_bytes(key, KEY_BYTES, 'subset public key')
        lamport.require_bytes(signature, SIGNATURE_BYTES, 'subset signature')
        expected = b''.join(_slot(key, i) for i in _selected(digest))
        actual = b''.join(sha256(_slot(signature, i)).digest() for i in range(SIGNATURE_BYTES // 32))
        return compare_digest(expected, actual)
    except ValueError:
        return False


def proof(key, digest, signature):
    if not verify_digest(key, digest, signature):
        raise ValueError('invalid fixed-weight Lamport signature from external signer')
    result = bytearray(key)
    for raw_index, slot in enumerate(_selected(digest)):
        result[32 * slot:32 * (slot + 1)] = _slot(signature, raw_index)
    return bytes(result)


class OneTimeSigner(lamport.OneTimeSigner):
    """Process-local demonstration of subset signing with independent keys."""
    _public_key = staticmethod(public_key)
    _sign_digest = staticmethod(sign_digest)

"""Lamport SHA-256 OTS, 256 bits, byte order then LSB-first within each byte.

Raw sign_digest is deliberately stateless. Use OneTimeSigner to prevent a second
signature within one process; durable anti-rollback state remains a wallet duty.
"""
from hashlib import sha256
from hmac import compare_digest
from secrets import token_bytes
from threading import Lock

KEY_BYTES = 16384
SIGNATURE_BYTES = 8192


def require_bytes(value, size, label):
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f'{label} must be {size} bytes')


def bits(digest):
    require_bytes(digest, 32, 'digest')
    return tuple((byte >> bit) & 1 for byte in digest for bit in range(8))


def public_key(secret):
    require_bytes(secret, KEY_BYTES, 'secret key')
    return b''.join(sha256(secret[i:i+32]).digest() for i in range(0, KEY_BYTES, 32))


def generate_keypair():
    secret = token_bytes(KEY_BYTES)
    return secret, public_key(secret)


def sign_digest(secret, digest):
    """Low-level primitive: caller MUST ensure this key is never reused."""
    require_bytes(secret, KEY_BYTES, 'secret key')
    return b''.join(secret[(2*i+b)*32:(2*i+b+1)*32] for i,b in enumerate(bits(digest)))


def verify_digest(key, digest, signature):
    try:
        require_bytes(key, KEY_BYTES, 'public key')
        require_bytes(signature, SIGNATURE_BYTES, 'signature')
        selected = b''.join(key[(2*i+b)*32:(2*i+b+1)*32] for i,b in enumerate(bits(digest)))
        hashed = b''.join(sha256(signature[i:i+32]).digest() for i in range(0, SIGNATURE_BYTES, 32))
        return compare_digest(selected, hashed)
    except ValueError:
        return False


class OneTimeSigner:
    """Thread-safe, process-local guard. Not persistent, non-copyable secure storage."""
    _public_key = staticmethod(public_key)
    _sign_digest = staticmethod(sign_digest)

    def __init__(self, secret):
        self.public_key = self._public_key(secret)
        self._secret = secret
        self._lock = Lock()

    def sign(self, digest):
        require_bytes(digest, 32, 'digest')  # malformed requests do not consume the key
        with self._lock:
            if self._secret is None:
                raise ValueError('one-time key already consumed')
            secret, self._secret = self._secret, None  # consume before disclosure
            return self._sign_digest(secret, digest)

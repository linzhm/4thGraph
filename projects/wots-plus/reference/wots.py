"""WOTSP-SHA2_256 chains and a compact public key for the BSV payment template.

The 64-byte template key contains the public seed and SHA-256 of the 67 chain
endpoints. An XMSS key uses a different encoding and commits to an L-tree.
"""

from hashlib import sha256
from hmac import compare_digest
from secrets import token_bytes
from threading import Lock

N = 32
W = 16
CHAINS = 67
KEY_BYTES = 2 * N
SIGNATURE_BYTES = CHAINS * N

_F_PREFIX = bytes(N)
_PRF_PREFIX = (3).to_bytes(N, "big")
_KEYGEN_PREFIX = (4).to_bytes(N, "big")
_BASE_ADDRESS = bytes(20)


def _require_bytes(value, size, label):
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{label} must be {size} bytes")


def digits(digest):
    """Return 64 message nibbles and 3 checksum nibbles, high nibble first."""
    _require_bytes(digest, N, "digest")
    message = tuple(nibble for byte in digest for nibble in (byte >> 4, byte & 15))
    checksum = sum(W - 1 - nibble for nibble in message)
    return message + (checksum >> 8, (checksum >> 4) & 15, checksum & 15)


def _prf(seed, value):
    return sha256(_PRF_PREFIX + seed + value).digest()


def _chain_address(chain_index):
    return _BASE_ADDRESS + chain_index.to_bytes(4, "big")


def _chain_start(secret_seed, public_seed, chain_index):
    # Match the optional pseudorandom expansion in xmss-reference, with its
    # own domain and the OTS address's hash and keyAndMask words set to zero.
    address = _chain_address(chain_index) + bytes(8)
    return sha256(_KEYGEN_PREFIX + secret_seed + public_seed + address).digest()


def _chain(value, public_seed, chain_index, start, stop):
    chain_address = _chain_address(chain_index)
    for step in range(start, stop):
        hash_address = chain_address + step.to_bytes(4, "big")
        key = _prf(public_seed, hash_address + b"\x00\x00\x00\x00")
        mask = _prf(public_seed, hash_address + b"\x00\x00\x00\x01")
        masked = bytes(left ^ right for left, right in zip(value, mask, strict=True))
        value = sha256(_F_PREFIX + key + masked).digest()
    return value


def public_key(secret_seed, public_seed):
    _require_bytes(secret_seed, N, "secret seed")
    _require_bytes(public_seed, N, "public seed")
    endpoints = b"".join(
        _chain(_chain_start(secret_seed, public_seed, index), public_seed, index, 0, W - 1)
        for index in range(CHAINS)
    )
    return public_seed + sha256(endpoints).digest()


def generate_keypair():
    """Return (secret_seed, compact_public_key) for a single WOTS+ key."""
    secret_seed = token_bytes(N)
    public_seed = token_bytes(N)
    return secret_seed, public_key(secret_seed, public_seed)


def sign_digest(secret_seed, public_seed, digest):
    """Sign one digest. The caller is responsible for durable key consumption."""
    _require_bytes(secret_seed, N, "secret seed")
    _require_bytes(public_seed, N, "public seed")
    return b"".join(
        _chain(_chain_start(secret_seed, public_seed, index), public_seed, index, 0, digit)
        for index, digit in enumerate(digits(digest))
    )


def verify_digest(key, digest, signature):
    try:
        _require_bytes(key, KEY_BYTES, "public key")
        _require_bytes(signature, SIGNATURE_BYTES, "signature")
        message_digits = digits(digest)
    except ValueError:
        return False

    public_seed, expected_commitment = key[:N], key[N:]
    endpoints = b"".join(
        _chain(signature[index * N:(index + 1) * N], public_seed, index, digit, W - 1)
        for index, digit in enumerate(message_digits)
    )
    return compare_digest(sha256(endpoints).digest(), expected_commitment)


class OneTimeSigner:
    """Process-local guard for reference use. Production needs a durable signer."""

    def __init__(self, secret_seed, public_seed):
        self.public_key = public_key(secret_seed, public_seed)
        self._secret_seed = secret_seed
        self._public_seed = public_seed
        self._lock = Lock()

    def sign(self, digest):
        _require_bytes(digest, N, "digest")
        with self._lock:
            if self._secret_seed is None:
                raise ValueError("one-time key already consumed")
            secret_seed, self._secret_seed = self._secret_seed, None
        return sign_digest(secret_seed, self._public_seed, digest)

    __call__ = sign

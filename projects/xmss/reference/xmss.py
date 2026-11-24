"""Public verifier for RFC 8391 XMSS-SHA2_10_256."""

from hashlib import sha256
from hmac import compare_digest

N = 32
HEIGHT = 10
LEAVES = 1 << HEIGHT
CHAINS = 67
INDEX_BYTES = 4
WOTS_BYTES = CHAINS * N
SIGNATURE_BYTES = INDEX_BYTES + N + WOTS_BYTES + HEIGHT * N
OID = b'\x00\x00\x00\x01'
KEY_BYTES = len(OID) + 2 * N


def key_parts(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != KEY_BYTES or not public_key.startswith(OID):
        raise ValueError('expected an XMSS-SHA2_10_256 public key')
    return public_key[4:36], public_key[36:]


def _hash(domain, payload):
    return sha256(domain.to_bytes(N, 'big') + payload).digest()


def _address(kind, slot, height, position, mask):
    words = (kind, slot, height, position, mask)
    return bytes(12) + b''.join(word.to_bytes(4, 'big') for word in words)


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _node(left, right, seed, kind, slot, height, index):
    prefix = seed + _address(kind, slot, height, index, 0)[:-4]
    key, mask_left, mask_right = (_hash(3, prefix + mask.to_bytes(4, 'big')) for mask in range(3))
    return _hash(1, key + _xor(left, mask_left) + _xor(right, mask_right))


def _digits(digest):
    message = tuple(nibble for value in digest for nibble in (value >> 4, value & 15))
    checksum = sum(15 - digit for digit in message)
    return message + (checksum >> 8, (checksum >> 4) & 15, checksum & 15)


def _chain(value, seed, leaf_index, chain, start, stop):
    for step in range(start, stop):
        prefix = seed + _address(0, leaf_index, chain, step, 0)[:-4]
        key = _hash(3, prefix + b'\x00\x00\x00\x00')
        mask = _hash(3, prefix + b'\x00\x00\x00\x01')
        value = _hash(0, key + _xor(value, mask))
    return value


def _endpoints(signature, digest, seed, leaf_index):
    for chain, digit in enumerate(_digits(digest)):
        start = signature[chain * N:(chain + 1) * N]
        yield _chain(start, seed, leaf_index, chain, digit, 15)


def _ltree(endpoints, seed, index):
    height = 0
    while len(endpoints) > 1:
        branch = [
            _node(endpoints[position], endpoints[position + 1], seed, 1, index, height, position // 2)
            for position in range(0, len(endpoints) - 1, 2)
        ]
        if len(endpoints) & 1:
            branch.append(endpoints[-1])
        endpoints = branch
        height += 1
    return endpoints[0]


def verify(public_key, message, signature):
    """Verify the 2,500-byte signature over the complete supplied message."""
    try:
        root, seed = key_parts(public_key)
    except ValueError:
        return False
    if not isinstance(message, bytes) or not isinstance(signature, bytes) or len(signature) != SIGNATURE_BYTES:
        return False
    index = int.from_bytes(signature[:INDEX_BYTES], 'big')
    if index >= LEAVES:
        return False

    wots_start = INDEX_BYTES + N
    path_start = wots_start + WOTS_BYTES
    randomizer = signature[INDEX_BYTES:wots_start]
    digest = _hash(2, randomizer + root + index.to_bytes(N, 'big') + message)
    endpoints = list(_endpoints(signature[wots_start:path_start], digest, seed, index))
    node = _ltree(endpoints, seed, index)
    for height in range(HEIGHT):
        start = path_start + height * N
        sibling = signature[start:start + N]
        left, right = (sibling, node) if index & 1 else (node, sibling)
        index >>= 1
        node = _node(left, right, seed, 2, 0, height, index)
    return compare_digest(node, root)

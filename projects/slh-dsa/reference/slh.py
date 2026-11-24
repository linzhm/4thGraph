"""Reference verifier for pure SLH-DSA-SHA2-128s with an empty context."""

from hashlib import sha256
from hmac import compare_digest
from struct import pack


N = 16
KEY_BYTES = 2 * N
WOTS_CHAINS = 35
FORS_TREES = 14
FORS_HEIGHT = 12
XMSS_HEIGHT = 9
XMSS_LAYERS = 7

FORS_TREE_BYTES = (FORS_HEIGHT + 1) * N
FORS_BYTES = FORS_TREES * FORS_TREE_BYTES
WOTS_BYTES = WOTS_CHAINS * N
XMSS_BYTES = WOTS_BYTES + XMSS_HEIGHT * N
SIGNATURE_BYTES = N + FORS_BYTES + XMSS_LAYERS * XMSS_BYTES

WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4


def _address(layer, tree, kind, key_pair, height_or_chain=0, index_or_step=0):
    """Serialize the 22-byte SHA2 compressed address (FIPS 205 §11.2)."""
    return pack('>BQBIII', layer, tree, kind, key_pair, height_or_chain, index_or_step)


def _hash_node(seed_block, address, node_bytes):
    # F, H and T_l share this definition for SHA2 security category 1.
    return sha256(seed_block + address + node_bytes).digest()[:N]


def _message_digest(randomizer, public_key, message):
    public_seed = public_key[:N]
    # Pure signing encodes the empty context as two zero bytes. MGF1 needs
    # only counter zero when producing a 30-byte digest from SHA-256.
    hashed = sha256(randomizer + public_key + b'\0\0' + message).digest()
    return sha256(randomizer + public_seed + hashed + bytes(4)).digest()[:30]


def _merkle_root(seed_block, layer, tree, kind, key_pair, index, node, path):
    for offset in range(0, len(path), N):
        sibling = path[offset:offset + N]
        children = sibling + node if index & 1 else node + sibling
        index >>= 1
        address = _address(layer, tree, kind, key_pair, offset // N + 1, index)
        node = _hash_node(seed_block, address, children)
    return node


def _fors_root(seed_block, tree, leaf, digest, signature):
    # Exactly 168 bits, read big-endian in fourteen 12-bit groups.
    index_bits = int.from_bytes(digest, 'big')
    roots = []
    for branch in range(FORS_TREES):
        remaining_bits = (FORS_TREES - 1 - branch) * FORS_HEIGHT
        index = (branch << FORS_HEIGHT) | ((index_bits >> remaining_bits) & 0xfff)
        start = branch * FORS_TREE_BYTES
        end = start + FORS_TREE_BYTES
        address = _address(0, tree, FORS_TREE, leaf, 0, index)
        node = _hash_node(seed_block, address, signature[start:start + N])
        roots.append(_merkle_root(
            seed_block, 0, tree, FORS_TREE, leaf, index, node, signature[start + N:end]
        ))
    return _hash_node(seed_block, _address(0, tree, FORS_ROOTS, leaf), b''.join(roots))


def _wots_pk(seed_block, layer, tree, leaf, message, signature):
    digits = [digit for byte in message for digit in (byte >> 4, byte & 15)]
    checksum = 15 * (2 * N) - sum(digits)
    digits.extend((checksum >> 8, (checksum >> 4) & 15, checksum & 15))

    endpoints = []
    for chain, digit in enumerate(digits):
        node = signature[chain * N:(chain + 1) * N]
        for step in range(digit, 15):
            node = _hash_node(seed_block, _address(layer, tree, WOTS_HASH, leaf, chain, step), node)
        endpoints.append(node)
    return _hash_node(seed_block, _address(layer, tree, WOTS_PK, leaf), b''.join(endpoints))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a raw FIPS 205 key and signature against a pure-mode message."""
    if (not isinstance(public_key, bytes) or len(public_key) != KEY_BYTES
            or not isinstance(signature, bytes) or len(signature) != SIGNATURE_BYTES
            or not isinstance(message, bytes)):
        return False

    seed_block = public_key[:N] + bytes(64 - N)
    root = public_key[N:]
    digest = _message_digest(signature[:N], public_key, message)
    tree = int.from_bytes(digest[21:28], 'big') & ((1 << 54) - 1)
    leaf = int.from_bytes(digest[28:], 'big') & ((1 << XMSS_HEIGHT) - 1)

    offset = N + FORS_BYTES
    node = _fors_root(seed_block, tree, leaf, digest[:21], signature[N:offset])
    for layer in range(XMSS_LAYERS):
        end = offset + XMSS_BYTES
        node = _wots_pk(seed_block, layer, tree, leaf, node, signature[offset:offset + WOTS_BYTES])
        node = _merkle_root(seed_block, layer, tree, TREE, 0, leaf, node, signature[offset + WOTS_BYTES:end])
        offset = end
        leaf, tree = tree & ((1 << XMSS_HEIGHT) - 1), tree >> XMSS_HEIGHT

    return compare_digest(node, root)

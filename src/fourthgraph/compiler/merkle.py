"""Lower bounded, ordered SHA-256 Merkle paths to BSV Script."""

from hashlib import sha256

from fourthgraph.bsv.script import asm, number
from fourthgraph.compiler.wordsets import Primitive, check_byte_size, push_value

MERKLE_ROOT = "merkle-sha256-root"
MAX_MERKLE_DEPTH = 32
DIGEST_BYTES = 32


def merkle_sha256_root(depth, tag):
    path_bytes = depth * DIGEST_BYTES
    domain_size = 1 << depth

    def root(node, path, position):
        check_byte_size(node, DIGEST_BYTES)
        check_byte_size(path, path_bytes)
        if not 0 <= position < domain_size:
            raise ValueError("Merkle position is outside the declared tree")
        for offset in range(0, path_bytes, DIGEST_BYTES):
            sibling = path[offset:offset + DIGEST_BYTES]
            pair = sibling + node if position & 1 else node + sibling
            node = sha256(tag + pair).digest()
            position >>= 1
        return (node,)

    # Check shape once, then maintain (index node unread-path) between levels.
    header = (
        asm("OP_DUP OP_0") + number(domain_size) + asm("OP_WITHIN OP_VERIFY OP_ROT OP_SIZE")
        + number(DIGEST_BYTES) + asm("OP_NUMEQUALVERIFY OP_ROT OP_SIZE")
        + number(path_bytes) + asm("OP_NUMEQUALVERIFY")
    )
    if depth:
        combine = asm("OP_IF OP_SWAP OP_ENDIF OP_CAT") + push_value(tag) + asm("OP_SWAP OP_CAT OP_SHA256")
        step = (
            number(DIGEST_BYTES) + asm("OP_SPLIT OP_TOALTSTACK OP_ROT OP_DUP OP_2 OP_MOD")
            + asm("OP_SWAP OP_2 OP_DIV OP_TOALTSTACK") + combine
            + asm("OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK")
        )
        # The last sibling is the entire suffix, and its parent needs no index.
        code = header + step * (depth - 1) + asm("OP_ROT OP_2 OP_MOD") + combine
    else:
        code = header + asm("OP_DROP OP_NIP")
    return Primitive(
        ("bytes", "bytes", "u32"), ("bytes",), code, root,
        "ordered tagged SHA-256 Merkle path", may_fail=True, repeatable=True,
        expansion_cost=len(code),
    )

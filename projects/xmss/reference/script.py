"""Generate an XMSS-SHA2_10_256 verifier and a transaction-bound payment lock."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.pushtx import authorization_checks, check_binding
from shared.script import asm, number, push
from shared.wots_sha2_script import endpoints_script
from xmss import CHAINS, HEIGHT, LEAVES, N, SIGNATURE_BYTES, WOTS_BYTES, key_parts

_TAG = asm('OP_NOP OP_NOP OP_NOP OP_NOP')
ORDINARY_CODE = _TAG + asm('OP_ENDIF OP_CHECKSIG')
COMPANION_CODE = _TAG + asm('OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR') + ORDINARY_CODE


def _word(value):
    return value.to_bytes(4, 'big')


def _domain(value):
    return value.to_bytes(N, 'big')


_REVERSE4 = asm('OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK') * 3 + asm('OP_FROMALTSTACK OP_CAT') * 3
_DECODE_INDEX = _REVERSE4 + push(b'\x00') + asm('OP_CAT OP_BIN2NUM')


def _rand_hash():
    # Entry suffix: left||right, PRF domain/seed/address without keyAndMask.
    code = asm('OP_DUP') + push(_word(0)) + asm('OP_CAT OP_SHA256 OP_TOALTSTACK')
    code += asm('OP_DUP') + push(_word(1)) + asm('OP_CAT OP_SHA256 OP_SWAP')
    code += push(_word(2)) + asm('OP_CAT OP_SHA256 OP_CAT OP_XOR')
    code += asm('OP_FROMALTSTACK OP_SWAP OP_CAT')
    return code + push(_domain(1)) + asm('OP_SWAP OP_CAT OP_SHA256')


def _ltree(seed):
    # Entry suffix: leaf index in big-endian bytes, packed WOTS+ endpoints.
    prefix = _domain(3) + seed + bytes(12) + _word(1)
    code = bytearray()
    count = CHAINS
    height = 0
    while count > 1:
        code += asm('OP_0 OP_TOALTSTACK')
        for position in range(count // 2):
            code += number(2 * N) + asm('OP_SPLIT OP_SWAP OP_2 OP_PICK')
            code += push(prefix) + asm('OP_SWAP OP_CAT')
            code += push(_word(height) + _word(position)) + asm('OP_CAT') + _rand_hash()
            code += asm('OP_FROMALTSTACK OP_SWAP OP_CAT OP_TOALTSTACK')
        # An odd final endpoint passes through to the next level unchanged.
        code += asm('OP_FROMALTSTACK OP_SWAP OP_CAT')
        count = (count + 1) // 2
        height += 1
    return bytes(code)


def _root(seed, root):
    # Entry suffix: leaf index, L-tree leaf. The path is at altstack top.
    code = bytearray(asm('OP_FROMALTSTACK OP_ROT') + _DECODE_INDEX + asm('OP_ROT'))
    for height in range(HEIGHT):
        # Stack: remaining path, current index, current node. Order the pair
        # with the current index's low bit, then hash with its parent index.
        code += asm('OP_ROT') + number(N) + asm('OP_SPLIT OP_SWAP OP_2SWAP OP_ROT')
        code += asm('OP_2 OP_PICK OP_2 OP_MOD OP_IF OP_SWAP OP_ENDIF OP_CAT')
        code += asm('OP_SWAP OP_2 OP_DIV OP_SWAP OP_OVER OP_4 OP_NUM2BIN') + _REVERSE4
        prefix = _domain(3) + seed + bytes(12) + _word(2) + _word(0) + _word(height)
        code += push(prefix) + asm('OP_SWAP OP_CAT') + _rand_hash()
    code += push(root) + asm('OP_EQUALVERIFY OP_2DROP')
    return bytes(code)


def verifier(public_key):
    """Consume signature and message while preserving the caller's altstack."""
    root, seed = key_parts(public_key)
    # [signature, message] -> [message, index, R], keep WOTS and path on altstack.
    code = asm('OP_SWAP OP_4 OP_SPLIT') + number(N) + asm('OP_SPLIT')
    code += number(WOTS_BYTES) + asm('OP_SPLIT OP_TOALTSTACK OP_TOALTSTACK')
    # H_msg binds the nonce, root, 32-byte big-endian index and complete message.
    code += asm('OP_ROT OP_TOALTSTACK') + push(_domain(2)) + asm('OP_SWAP OP_CAT')
    code += push(root + bytes(28)) + asm('OP_CAT OP_OVER OP_CAT OP_FROMALTSTACK OP_CAT OP_SHA256')
    code += asm('OP_OVER') + _DECODE_INDEX + asm('OP_0') + number(LEAVES) + asm('OP_WITHIN OP_VERIFY')
    # Address type 0 includes the signed leaf index in the WOTS+ address.
    code += asm('OP_FROMALTSTACK OP_SWAP OP_2 OP_PICK')
    code += push(_domain(3) + seed + bytes(16)) + asm('OP_SWAP OP_CAT OP_ROT OP_ROT')
    code += endpoints_script() + asm('OP_ROT OP_DROP OP_NIP')
    return code + _ltree(seed) + _root(seed, root)


def locking_script(public_key, *, transaction=True):
    """Build a payment lock or a detached message verifier for tests."""
    size = asm('OP_SIZE') + number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY')
    if not transaction:
        return asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY') + size + asm('OP_SWAP') + verifier(public_key) + asm('OP_1')
    shape = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    shape += size + asm('OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return shape + verifier(public_key) + asm('OP_FROMALTSTACK') + check_binding(COMPANION_CODE)

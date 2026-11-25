"""Emit the RFC 8391 verifier and a transaction-bound BSV payment lock."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.pushtx import authorization_checks, check_binding
from shared.script import asm, number, push
from wots import CHAINS, KEY_BYTES, N, SIGNATURE_BYTES, W

# ScriptCode suffixes differ from Lamport; the extra OP_NOPs are domain tags.
ORDINARY_CODE = asm('OP_NOP OP_ENDIF OP_CHECKSIG')
COMPANION_CODE = asm('OP_NOP OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR') + ORDINARY_CODE


def _message_digits():
    # Entry: signature, digest. Leave the checksum on stack and the message
    # nibbles on altstack, with the first (high nibble of byte zero) on top.
    code = bytearray(asm('OP_0'))
    for byte_index in reversed(range(N)):
        code += asm('OP_SWAP') + number(byte_index) + asm('OP_SPLIT')
        code += push(b'\0') + asm('OP_CAT OP_BIN2NUM')
        code += asm('OP_DUP OP_16 OP_MOD OP_DUP OP_TOALTSTACK')
        code += asm('OP_SWAP OP_16 OP_DIV OP_DUP OP_TOALTSTACK OP_ADD OP_ROT OP_ADD')
    maximum = 2 * N * (W - 1)
    return bytes(code) + asm('OP_NIP') + number(maximum) + asm('OP_SWAP OP_SUB')


def _chain(index, *, cached_constants):
    # Entry: PRF prefix, checksum, accumulated endpoints, remaining signature.
    code = bytearray(number(N) + asm('OP_SPLIT OP_SWAP OP_4 OP_PICK'))
    code += push(index.to_bytes(4, 'big')) + asm('OP_CAT OP_SWAP OP_FROMALTSTACK')
    if cached_constants:
        # Fixed depths include the PRF prefix, checksum, and current chain state.
        mask_zero = asm('OP_10 OP_PICK')
        mask_one = asm('OP_9 OP_PICK')
        function_prefix = asm('OP_9 OP_PICK')
    else:
        mask_zero = asm('OP_0 OP_4 OP_NUM2BIN')
        mask_one = push(b'\0\0\0\1')
        function_prefix = asm('OP_0') + number(N) + asm('OP_NUM2BIN')
    # Complete the hash chain from the signed digit through step 14. The last
    # eight bytes of ADRS encode the step and keyAndMask in big-endian order.
    for step in range(W - 1):
        code += asm('OP_DUP') + number(step) + asm('OP_GREATERTHAN OP_NOTIF OP_SWAP')
        # There are eleven live items above the step table at this access.
        step_bytes = (number(11 + W - 2 - step) + asm('OP_PICK') if cached_constants == 'steps'
                      else push(step.to_bytes(4, 'big')))
        code += asm('OP_2 OP_PICK') + step_bytes + asm('OP_CAT OP_DUP')
        code += mask_zero + asm('OP_CAT OP_SHA256 OP_SWAP')
        code += mask_one + asm('OP_CAT OP_SHA256 OP_ROT OP_XOR OP_CAT')
        code += function_prefix + asm('OP_SWAP OP_CAT OP_SHA256 OP_SWAP OP_ENDIF')
    # Drop the digit and chain prefix, then append the new endpoint.
    code += asm('OP_DROP OP_NIP OP_ROT OP_SWAP OP_CAT OP_SWAP')
    return bytes(code)


def verifier(key, *, cached_constants=False):
    """Consume packed signature and digest, preserving existing altstack items."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError('WOTS+ public key must be 64 bytes')
    public_seed, commitment = key[:N], key[N:]
    prf_prefix = (3).to_bytes(N, 'big') + public_seed + bytes(20)
    if type(cached_constants) is not bool and cached_constants != 'steps':
        raise ValueError('unknown WOTS+ constant cache profile')
    if cached_constants:
        code = bytearray()
        if cached_constants == 'steps':
            code += b''.join(push(step.to_bytes(4, 'big')) for step in range(W - 1))
        code += push(bytes(N)) + push(bytes(4)) + push(b'\0\0\0\1')
        depth = 5 + (W - 1 if cached_constants == 'steps' else 0)
        code += push(prf_prefix) + (number(depth) + asm('OP_ROLL')) * 2
    else:
        code = bytearray(push(prf_prefix) + asm('OP_ROT OP_ROT'))
    code += _message_digits() + asm('OP_SWAP OP_0 OP_SWAP')
    for index in range(2 * N):
        code += _chain(index, cached_constants=cached_constants)
    # Three checksum nibbles, most significant first when popped from altstack.
    code += asm('OP_2 OP_PICK OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV')
    code += asm('OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV OP_TOALTSTACK')
    for index in range(2 * N, CHAINS):
        code += _chain(index, cached_constants=cached_constants)
    code += asm('OP_0 OP_EQUALVERIFY OP_SHA256') + push(commitment)
    code += asm('OP_EQUALVERIFY OP_2DROP')
    if cached_constants:
        code += asm('OP_2DROP OP_DROP')
        if cached_constants == 'steps':
            code += asm('OP_2DROP') * ((W - 1) // 2) + asm('OP_DROP')
    return bytes(code)


def locking_script(key, *, transaction=True, cached_constants=False):
    """Build a payment lock or a detached digest verifier for tests."""
    if not transaction:
        shape = asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY OP_OVER OP_SIZE')
        shape += number(N) + asm('OP_NUMEQUALVERIFY OP_DROP OP_SIZE')
        shape += number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY OP_SWAP')
        return shape + verifier(key, cached_constants=cached_constants) + asm('OP_1')
    shape = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    shape += asm('OP_SIZE') + number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY')
    shape += asm('OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return (shape + verifier(key, cached_constants=cached_constants)
            + asm('OP_FROMALTSTACK') + check_binding(COMPANION_CODE))

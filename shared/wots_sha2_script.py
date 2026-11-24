"""Emit the RFC 8391 SHA-256 WOTS+ endpoint reconstruction."""

from functools import cache

from .script import asm, number, push

N = 32
W = 16
CHAINS = 67


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


def _chain(index):
    # Entry: PRF prefix, checksum, accumulated endpoints, remaining signature.
    code = bytearray(number(N) + asm('OP_SPLIT OP_SWAP OP_4 OP_PICK'))
    code += push(index.to_bytes(4, 'big')) + asm('OP_CAT OP_SWAP OP_FROMALTSTACK')
    # Complete the hash chain from the signed digit through step 14. The last
    # eight bytes of ADRS encode the step and keyAndMask in big-endian order.
    for step in range(W - 1):
        code += asm('OP_DUP') + number(step) + asm('OP_GREATERTHAN OP_NOTIF OP_SWAP')
        code += asm('OP_2 OP_PICK') + push(step.to_bytes(4, 'big')) + asm('OP_CAT OP_DUP')
        code += asm('OP_0 OP_4 OP_NUM2BIN OP_CAT OP_SHA256 OP_SWAP')
        code += push(b'\0\0\0\1') + asm('OP_CAT OP_SHA256 OP_ROT OP_XOR OP_CAT')
        code += asm('OP_0') + number(N) + asm('OP_NUM2BIN OP_SWAP OP_CAT OP_SHA256 OP_SWAP OP_ENDIF')
    # Drop the digit and chain prefix, then append the new endpoint.
    code += asm('OP_DROP OP_NIP OP_ROT OP_SWAP OP_CAT OP_SWAP')
    return bytes(code)


@cache
def endpoints_script():
    """Consume a packed WOTS+ signature and recover its chain endpoints.

    Entry suffix: PRF prefix, signature, digest.
    Exit suffix: PRF prefix, checksum, 67 concatenated endpoints.
    Existing alternate-stack items are preserved.
    """
    code = bytearray(_message_digits()) + asm('OP_SWAP OP_0 OP_SWAP')
    for index in range(2 * N):
        code += _chain(index)
    # Three checksum nibbles, most significant first when popped from altstack.
    code += asm('OP_2 OP_PICK OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV')
    code += asm('OP_DUP OP_16 OP_MOD OP_TOALTSTACK OP_16 OP_DIV OP_TOALTSTACK')
    for index in range(2 * N, CHAINS):
        code += _chain(index)
    return bytes(code) + asm('OP_0 OP_EQUALVERIFY')

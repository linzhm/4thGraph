"""FIPS 204 UseHint and w1Encode over the reconstructed ML-DSA-44 rows."""

from functools import cache

from ntt_script import COEFFICIENT_BYTES, POLYNOMIAL_BYTES
from polynomial import DEGREE, MODULUS
from fourthgraph.bsv.script import asm, number, push

_ROWS = 4
_HIGH_MODULUS = 44
_LOW_MODULUS = (MODULUS - 1) // _HIGH_MODULUS
_GAMMA2 = _LOW_MODULUS // 2


def _read_bytes(depth, offset, width):
    return (number(depth) + asm("OP_PICK") + number(offset) + asm("OP_SPLIT OP_NIP")
            + number(width) + asm("OP_SPLIT OP_DROP"))


def _decompose():
    # Output [low, high], including the q-1 boundary in FIPS 204 Algorithm 36.
    code = asm("OP_DUP") + number(_LOW_MODULUS) + asm("OP_MOD OP_DUP")
    code += number(_GAMMA2) + asm("OP_GREATERTHAN OP_IF")
    code += number(_LOW_MODULUS) + asm("OP_SUB OP_ENDIF OP_TUCK OP_SUB OP_DUP")
    code += number(MODULUS - 1) + asm("OP_NUMEQUAL OP_IF OP_DROP OP_1SUB OP_0 OP_ELSE")
    return code + number(_LOW_MODULUS) + asm("OP_DIV OP_ENDIF")


def _hint_is_clear(index):
    return (_read_bytes(4, index // 8, 1) + push(bytes((1 << (index % 8),)))
            + asm("OP_AND") + push(b"\0") + asm("OP_EQUAL"))


def _compact_use_hint(index):
    # Compute the unreduced high part in [0, 44] and whether the centered
    # low part is positive. At high == 44 the low part is negative, including
    # q-1, and reducing the high part modulo 44 gives the FIPS 204 wrap.
    code = asm("OP_DUP") + number(_GAMMA2 - 1) + asm("OP_ADD")
    code += number(_LOW_MODULUS) + asm("OP_DIV OP_TUCK")
    code += number(_LOW_MODULUS) + asm("OP_MUL OP_GREATERTHAN")
    code += _hint_is_clear(index)
    code += asm("OP_NOTIF OP_IF OP_1ADD OP_ELSE OP_1SUB OP_ENDIF OP_ELSE OP_DROP OP_ENDIF")
    return code + number(_HIGH_MODULUS) + asm("OP_ADD") + number(_HIGH_MODULUS) + asm("OP_MOD")


@cache
def apply_hints_script(*, compact=True):
    """Consume the packed four canonical residue rows and the 128-byte hint bitset.

    The hint bitset uses one LSB-first bit per coefficient, in row order. The
    caller checks the original signature's canonical hint encoding. The
    result is the 768-byte w1Encode output used by ML-DSA-44 verification.
    """
    code = bytearray(asm("OP_SIZE") + number(_ROWS * DEGREE // 8) + asm("OP_NUMEQUALVERIFY OP_OVER OP_SIZE"))
    code += number(_ROWS * POLYNOMIAL_BYTES) + asm("OP_NUMEQUALVERIFY OP_DROP OP_0")
    decompose = _decompose()
    for first in range(0, _ROWS * DEGREE, 4):
        code += asm("OP_0")
        for digit in range(4):
            index = first + digit
            code += _read_bytes(3, index * COEFFICIENT_BYTES, COEFFICIENT_BYTES)
            code += asm("OP_BIN2NUM")
            if compact:
                code += _compact_use_hint(index)
            else:
                code += decompose + _hint_is_clear(index) + asm("OP_NOTIF")
                code += asm("OP_SWAP OP_0 OP_GREATERTHAN OP_IF OP_1ADD OP_ELSE OP_1SUB OP_ENDIF")
                code += number(_HIGH_MODULUS) + asm("OP_ADD") + number(_HIGH_MODULUS) + asm("OP_MOD")
                code += asm("OP_ELSE OP_NIP OP_ENDIF")
            if digit:
                code += number(1 << (6 * digit)) + asm("OP_MUL")
            code += asm("OP_ADD")
        # Script arithmetic needs a sign byte for 24-bit unsigned results.
        code += asm("OP_4 OP_NUM2BIN OP_3 OP_SPLIT OP_DROP OP_CAT")
    return bytes(code) + asm("OP_ROT OP_DROP OP_NIP")

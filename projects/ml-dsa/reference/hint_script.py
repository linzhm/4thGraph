"""FIPS 204 UseHint and w1Encode over the reconstructed ML-DSA-44 rows."""

from functools import cache

from ntt_script import COEFFICIENT_BYTES, POLYNOMIAL_BYTES
from polynomial import DEGREE, MODULUS
from signature_script import HINT_WEIGHT_LIMIT
from fourthgraph.bsv.script import asm, number, push

_ROWS = 4
_HIGH_MODULUS = 44
_LOW_MODULUS = (MODULUS - 1) // _HIGH_MODULUS
_GAMMA2 = _LOW_MODULUS // 2
_PACK_W1_GROUP = asm("OP_4 OP_NUM2BIN OP_3 OP_SPLIT OP_DROP")


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


def _unreduced_high():
    return number(_GAMMA2 - 1) + asm("OP_ADD") + number(_LOW_MODULUS) + asm("OP_DIV")


def _high_and_low_sign():
    # Compute the unreduced high part in [0, 44] and whether the centered
    # low part is positive. At high == 44 the low part is negative, including
    # q-1, and reducing the high part modulo 44 gives the FIPS 204 wrap.
    code = asm("OP_DUP") + _unreduced_high() + asm("OP_TUCK")
    return code + number(_LOW_MODULUS) + asm("OP_MUL OP_GREATERTHAN")


def _compact_use_hint(index):
    code = _high_and_low_sign() + _hint_is_clear(index)
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
        code += _PACK_W1_GROUP + asm("OP_CAT")
    return bytes(code) + asm("OP_ROT OP_DROP OP_NIP")


@cache
def apply_sparse_hints_script():
    """Consume canonical residue rows and the signature decoder's sparse indices."""
    # Form the unhinted w1 in one sequential scan of the residue bytes.
    scales = b"".join((1 << (6 * digit)).to_bytes(3, "little") for digit in range(4))
    code = push(scales) + asm("OP_ROT OP_ROT OP_OVER OP_SIZE")
    code += number(_ROWS * POLYNOMIAL_BYTES) + asm("OP_NUMEQUALVERIFY OP_0 OP_SWAP")
    high = _unreduced_high() + number(_HIGH_MODULUS) + asm("OP_MOD")
    shift = number(64) + asm("OP_MUL OP_SWAP")
    group = asm("OP_12 OP_SPLIT OP_SWAP OP_9 OP_SPLIT OP_BIN2NUM") + high
    for offset in (6, 3):
        group += shift + number(offset) + asm("OP_SPLIT OP_BIN2NUM") + high + asm("OP_ROT OP_ADD")
    group += shift + asm("OP_BIN2NUM") + high + asm("OP_ADD")
    group += _PACK_W1_GROUP + asm("OP_ROT OP_SWAP OP_CAT OP_SWAP")
    code += group * (_ROWS * DEGREE // 4) + asm("OP_DROP OP_SWAP")

    # [scales, residues, w1, indices]. For each checked index, find the
    # signed change in that digit and add it at the matching six-bit place.
    hint = asm("OP_SIZE OP_0NOTEQUAL OP_IF OP_2 OP_SPLIT OP_SWAP OP_BIN2NUM")
    hint += asm("OP_DUP OP_4 OP_PICK OP_SWAP OP_3 OP_MUL OP_SPLIT OP_NIP "
                "OP_3 OP_SPLIT OP_DROP OP_BIN2NUM")
    hint += _high_and_low_sign()
    modulus = number(_HIGH_MODULUS)
    hint += asm("OP_OVER") + modulus + asm("OP_MOD OP_TOALTSTACK")
    hint += asm("OP_IF OP_1ADD OP_ELSE OP_1SUB OP_ENDIF")
    hint += modulus + asm("OP_ADD") + modulus + asm("OP_MOD OP_FROMALTSTACK OP_SUB")
    hint += asm("OP_OVER OP_4 OP_MOD OP_3 OP_MUL OP_6 OP_PICK OP_SWAP OP_SPLIT OP_NIP "
                "OP_3 OP_SPLIT OP_DROP OP_BIN2NUM OP_MUL OP_TOALTSTACK")
    hint += asm("OP_4 OP_DIV OP_3 OP_MUL OP_ROT OP_SWAP OP_SPLIT OP_3 OP_SPLIT OP_SWAP")
    hint += push(b"\x00") + asm("OP_CAT OP_BIN2NUM OP_FROMALTSTACK OP_ADD")
    hint += _PACK_W1_GROUP + asm("OP_SWAP OP_CAT OP_CAT OP_SWAP OP_ENDIF")
    code += hint * HINT_WEIGHT_LIMIT
    return code + asm("OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP OP_NIP OP_NIP")

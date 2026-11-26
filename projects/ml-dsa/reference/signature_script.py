"""ML-DSA-44 signature decoding and response norm checking in Bitcoin Script.

This fragment implements FIPS 204 sigDecode and the verification norm bound.
It consumes a signature byte vector and exposes public arithmetic inputs for
subsequent verifier stages. It does not authorize a payment.
"""

from functools import cache
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from fips204 import SIGNATURE_BYTES
from ntt_script import COEFFICIENT_BYTES
from polynomial import DEGREE, MODULUS
from fourthgraph.bsv.script import asm, number, push

CHALLENGE_BYTES = 32
RESPONSE_COUNT = HINT_ROWS = 4
RESPONSE_BITS = 18
RESPONSE_PACKED_BYTES = RESPONSE_COUNT * DEGREE * RESPONSE_BITS // 8
RESPONSE_RESIDUE_BYTES = RESPONSE_COUNT * DEGREE * COEFFICIENT_BYTES
HINT_WEIGHT_LIMIT = 80
HINT_PACKED_BYTES = HINT_WEIGHT_LIMIT + HINT_ROWS
HINT_BITMAP_BYTES = HINT_ROWS * DEGREE // 8
GAMMA1 = 1 << 17
RESPONSE_NORM_LIMIT = GAMMA1 - 78

_UNSIGNED = push(b'\x00') + asm('OP_CAT OP_BIN2NUM')


@cache
def response_decode_script(*, signed=False, reuse_constants=False):
    """Replace packed z with four range-checked polynomials of three-byte coefficients."""
    code = bytearray(asm('OP_SIZE') + number(RESPONSE_PACKED_BYTES) + asm('OP_NUMEQUALVERIFY'))
    if signed and reuse_constants:
        return bytes(code) + _signed_response_with_constants()
    code += asm('OP_0 OP_TOALTSTACK')

    radix = number(1 << RESPONSE_BITS)
    # Decode four little-endian coefficients from each nine-byte group.
    begin_group = asm('OP_9 OP_SPLIT OP_SWAP') + _UNSIGNED
    residue = number(GAMMA1) + asm('OP_SWAP OP_SUB OP_DUP OP_ABS')
    residue += number(RESPONSE_NORM_LIMIT) + asm('OP_LESSTHAN OP_VERIFY')
    if not signed:
        residue += number(MODULUS) + asm('OP_ADD') + number(MODULUS) + asm('OP_MOD')
    residue += number(COEFFICIENT_BYTES) + asm('OP_NUM2BIN')
    residue += asm('OP_FROMALTSTACK OP_SWAP OP_CAT OP_TOALTSTACK')
    coefficient = asm('OP_DUP') + radix + asm('OP_MOD') + residue + radix + asm('OP_DIV')
    code += (begin_group + coefficient * 3 + residue) * (RESPONSE_COUNT * DEGREE // 4)
    return bytes(code) + asm('OP_DROP OP_FROMALTSTACK')


def _signed_response_with_constants():
    # Keep gamma1, the strict norm bound and the input radix under the
    # unread bytes. The accumulated output stays on the altstack.
    code = asm('OP_TOALTSTACK') + number(GAMMA1) + number(RESPONSE_NORM_LIMIT)
    code += number(1 << RESPONSE_BITS) + asm('OP_FROMALTSTACK OP_0 OP_TOALTSTACK')
    begin = asm('OP_9 OP_SPLIT OP_SWAP') + _UNSIGNED

    def checked_coefficient(depth):
        # Duplicating z for ABS puts the norm bound at the old gamma1 depth.
        copy_constant = number(depth) + asm('OP_PICK')
        return (copy_constant + asm('OP_SWAP OP_SUB OP_DUP OP_ABS') + copy_constant
                + asm('OP_LESSTHAN OP_VERIFY OP_3 OP_NUM2BIN OP_FROMALTSTACK OP_SWAP OP_CAT OP_TOALTSTACK'))

    low = asm('OP_DUP OP_3 OP_PICK OP_MOD') + checked_coefficient(5) + asm('OP_2 OP_PICK OP_DIV')
    group = begin + low * 3 + checked_coefficient(4)
    code += group * (RESPONSE_COUNT * DEGREE // 4)
    return code + asm('OP_2DROP OP_2DROP OP_FROMALTSTACK')


@cache
def hint_decode_script(*, compact=True, sparse=False):
    """Decode HintBitPack into bitmaps or ordered two-byte global indices."""
    code = bytearray(asm('OP_SIZE') + number(HINT_PACKED_BYTES) + asm('OP_NUMEQUALVERIFY'))
    code += number(HINT_WEIGHT_LIMIT) + asm('OP_SPLIT')
    if compact or sparse:
        return bytes(code) + _compact_hint_decode(sparse=sparse)
    code += asm('OP_0')

    # [remaining indices, remaining endpoints, previous endpoint] enters each
    # row. Validate the next endpoint and split off the indices it covers.
    row = bytearray(asm('OP_SWAP OP_1 OP_SPLIT OP_SWAP') + _UNSIGNED)
    row += asm('OP_DUP OP_0') + number(HINT_WEIGHT_LIMIT + 1) + asm('OP_WITHIN OP_VERIFY')
    row += asm('OP_DUP OP_3 OP_PICK OP_GREATERTHANOREQUAL OP_VERIFY')
    row += asm('OP_DUP OP_3 OP_ROLL OP_SUB OP_3 OP_ROLL OP_SWAP OP_SPLIT')
    row += asm('OP_SWAP OP_TOALTSTACK OP_ROT OP_ROT OP_FROMALTSTACK')
    row += push(bytes(DEGREE // 8)) + asm('OP_1NEGATE OP_ROT')

    # The top three items are [bitmap, last index, unprocessed row bytes].
    # For each occupied slot, the row index must strictly increase. Empty
    # slots simply skip the body for the remainder of this unrolled row.
    index = asm('OP_SIZE OP_0NOTEQUAL OP_IF OP_1 OP_SPLIT OP_SWAP') + _UNSIGNED
    index += asm('OP_DUP OP_3 OP_PICK OP_GREATERTHAN OP_VERIFY OP_ROT OP_DROP')
    # Byte-vector shift order is MSB-first. Flip the low three bits of the
    # shift distance to place the bit in LSB-first order inside each byte.
    index += asm('OP_DUP OP_2 OP_NUM2BIN') + push(b'\x07\x00') + asm('OP_XOR OP_BIN2NUM')
    most_significant_bit = b'\x80' + bytes(DEGREE // 8 - 1)
    index += push(most_significant_bit) + asm('OP_SWAP OP_RSHIFT')
    index += asm('OP_3 OP_ROLL OP_OR OP_ROT OP_ROT OP_SWAP OP_ENDIF')
    row += index * HINT_WEIGHT_LIMIT + asm('OP_2DROP OP_TOALTSTACK')
    code += row * HINT_ROWS

    # Padding is a byte-string equality check. Numeric zero would also admit
    # a final 0x80 byte under Script signed-magnitude decoding.
    code += asm('OP_2DROP OP_SIZE OP_0 OP_SWAP OP_NUM2BIN OP_EQUALVERIFY')
    code += asm('OP_FROMALTSTACK')
    code += asm('OP_FROMALTSTACK OP_SWAP OP_CAT') * (HINT_ROWS - 1)
    return bytes(code)


def _compact_hint_decode(*, sparse):
    # Check the four unsigned endpoints and the unused tail of the index array.
    endpoint = asm('OP_1 OP_SPLIT OP_SWAP') + _UNSIGNED + asm('OP_SWAP')
    code = endpoint * (HINT_ROWS - 1) + _UNSIGNED
    code += asm('OP_DUP') + number(HINT_WEIGHT_LIMIT) + asm('OP_LESSTHANOREQUAL OP_VERIFY')
    code += asm('OP_3 OP_PICK OP_3 OP_PICK OP_LESSTHANOREQUAL OP_VERIFY '
                'OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHANOREQUAL OP_VERIFY '
                'OP_2DUP OP_LESSTHANOREQUAL OP_VERIFY OP_4 OP_ROLL OP_SWAP OP_SPLIT')
    code += asm('OP_SIZE OP_0 OP_SWAP OP_NUM2BIN OP_EQUALVERIFY OP_TOALTSTACK')

    # [end0, end1, end2, (msb), cursor, output, previous index, remaining].
    # Global indices increase across row boundaries, including empty rows.
    bitmap_bytes = HINT_ROWS * DEGREE // 8
    if sparse:
        code += asm('OP_0 OP_0')
    else:
        code += push(b'\x80' + bytes(bitmap_bytes - 1))
        code += asm('OP_0 OP_0') + number(bitmap_bytes) + asm('OP_NUM2BIN')
    code += asm('OP_1NEGATE OP_FROMALTSTACK')
    index = asm('OP_SIZE OP_0NOTEQUAL OP_IF OP_1 OP_SPLIT OP_SWAP') + _UNSIGNED
    mask_slots = 0 if sparse else 1
    index += asm('OP_4 OP_PICK') + number(6 + mask_slots) + asm('OP_PICK OP_GREATERTHANOREQUAL')
    for depth in (8, 9):
        index += asm('OP_5 OP_PICK') + number(depth + mask_slots)
        index += asm('OP_PICK OP_GREATERTHANOREQUAL OP_ADD')
    index += number(DEGREE) + asm('OP_MUL OP_ADD OP_DUP OP_3 OP_PICK OP_GREATERTHAN OP_VERIFY OP_ROT OP_DROP')
    index += asm('OP_DUP OP_2 OP_NUM2BIN')
    if sparse:
        index += asm('OP_3 OP_ROLL OP_SWAP OP_CAT')
    else:
        # Convert the global index to a big-endian shift count for a LSB-first bitmap.
        index += push(b'\x07\x00') + asm('OP_XOR OP_BIN2NUM')
        index += asm('OP_5 OP_PICK OP_SWAP OP_RSHIFT OP_3 OP_ROLL OP_OR')
    index += asm('OP_ROT OP_ROT OP_SWAP')
    index += asm('OP_TOALTSTACK OP_TOALTSTACK OP_SWAP OP_1ADD OP_SWAP '
                 'OP_FROMALTSTACK OP_FROMALTSTACK OP_ENDIF')
    code += index * HINT_WEIGHT_LIMIT
    code += asm('OP_2DROP OP_TOALTSTACK OP_2DROP OP_2DROP')
    if not sparse:
        code += asm('OP_DROP')
    return code + asm('OP_FROMALTSTACK')


@cache
def signature_decode_script(*, compact=True, signed_response=False, sparse_hints=False):
    """Replace a signature with [c-tilde, z residues, decoded hints]."""
    code = asm('OP_SIZE') + number(SIGNATURE_BYTES) + asm('OP_NUMEQUALVERIFY')
    code += number(CHALLENGE_BYTES) + asm('OP_SPLIT')
    code += number(RESPONSE_PACKED_BYTES) + asm('OP_SPLIT')
    return (
        code + hint_decode_script(compact=compact, sparse=sparse_hints) + asm('OP_TOALTSTACK')
        + response_decode_script(signed=signed_response, reuse_constants=sparse_hints) + asm('OP_FROMALTSTACK')
    )

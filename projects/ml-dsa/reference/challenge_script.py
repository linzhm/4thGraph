"""ML-DSA-44 SampleInBall with an explicit Script XOF budget."""

from functools import cache

from fips204 import CHALLENGE_BYTES, CHALLENGE_SIGN_BYTES, CHALLENGE_WEIGHT, SAMPLE_IN_BALL_BYTES
from shake_script import shake256_script
from fourthgraph.bsv.script import asm, number, push
from polynomial import DEGREE, MODULUS

_COEFFICIENT_BYTES = 3
_UNSIGNED = push(b'\x00') + asm('OP_CAT OP_BIN2NUM')


def _replace_lane(lane_bytes, scale):
    # Suffix P, index, replacement -> P with that lane replaced.
    return (asm('OP_TOALTSTACK') + scale + asm('OP_SPLIT') + lane_bytes
            + asm('OP_SPLIT OP_NIP OP_FROMALTSTACK OP_SWAP OP_CAT OP_CAT'))


def _sample_byte(width, *, signed):
    lane_bytes = number(width)
    scale = b'' if signed else lane_bytes + asm('OP_MUL')
    replace_lane = _replace_lane(lane_bytes, scale)
    # Entry: remaining stream, sign bits, polynomial, next index.
    code = asm('OP_DUP') + number(DEGREE) + asm('OP_LESSTHAN OP_IF')
    code += asm('OP_3 OP_ROLL OP_1 OP_SPLIT OP_SWAP') + push(b'\x00')
    code += asm('OP_CAT OP_BIN2NUM OP_TOALTSTACK OP_2SWAP OP_3 OP_ROLL OP_FROMALTSTACK')
    # The candidate is accepted only when it is no greater than i.
    code += asm('OP_2DUP OP_LESSTHAN OP_NOTIF')
    code += asm('OP_2 OP_PICK OP_OVER') + scale + asm('OP_SPLIT OP_NIP') + lane_bytes + asm('OP_SPLIT OP_DROP')
    # Copy P[j] into P[i] before replacing P[j].
    code += asm('OP_TOALTSTACK OP_2 OP_PICK OP_2 OP_PICK OP_FROMALTSTACK') + replace_lane
    code += asm('OP_3 OP_ROLL OP_DROP OP_2 OP_ROLL OP_TOALTSTACK OP_SWAP')
    code += asm('OP_2 OP_PICK OP_2 OP_MOD OP_IF') + number(-1 if signed else MODULUS - 1)
    code += asm('OP_ELSE OP_1 OP_ENDIF') + lane_bytes + asm('OP_NUM2BIN') + replace_lane
    code += asm('OP_SWAP OP_2 OP_DIV OP_SWAP OP_FROMALTSTACK OP_1ADD')
    return code + asm('OP_ELSE OP_DROP OP_ENDIF OP_ENDIF')


@cache
def sample_from_stream_script(*, signed=False, search=False, find_by_borrow=False):
    """Decode a SHAKE256 prefix into three-byte residues or one-byte signed coefficients."""
    width = 1 if signed else _COEFFICIENT_BYTES
    shape = asm('OP_SIZE') + number(SAMPLE_IN_BALL_BYTES) + asm('OP_NUMEQUALVERIFY')
    if search and signed:
        return shape + _search_sample_script(find_by_borrow=find_by_borrow)
    shape += number(CHALLENGE_SIGN_BYTES) + asm('OP_SPLIT OP_SWAP')
    shape += _UNSIGNED + asm('OP_0')
    shape += number(DEGREE * width) + asm('OP_NUM2BIN') + number(DEGREE - CHALLENGE_WEIGHT)
    draws = _sample_byte(width, signed=signed) * (SAMPLE_IN_BALL_BYTES - CHALLENGE_SIGN_BYTES)
    # Discard all sampler state before returning the one exhaustion error.
    end = number(DEGREE) + asm('OP_NUMEQUAL OP_IF OP_NIP OP_NIP '
                               'OP_ELSE OP_2DROP OP_DROP OP_0 OP_VERIFY OP_ENDIF')
    return shape + draws + end


def _search_sample_script(*, find_by_borrow):
    """Find one acceptable byte per selection using parallel comparisons."""
    first = DEGREE - CHALLENGE_WEIGHT
    assert DEGREE == 256 and 128 <= first < DEGREE
    assert SAMPLE_IN_BALL_BYTES - CHALLENGE_SIGN_BYTES < DEGREE
    width = number(DEGREE)
    fit = number(DEGREE + 1) + asm('OP_NUM2BIN') + width + asm('OP_SPLIT OP_DROP')

    # [guard mask, byte multiplier, padding, signs, polynomial, unread draws].
    code = asm('OP_TOALTSTACK')
    for seed in (push(b'\x80'), asm('OP_1'), push(b'\xff')):
        code += seed + asm('OP_DUP OP_CAT') * (DEGREE.bit_length() - 1)
    code += asm('OP_FROMALTSTACK OP_8 OP_SPLIT OP_SWAP') + _UNSIGNED
    code += asm('OP_0') + width + asm('OP_NUM2BIN OP_ROT')

    # Fill unread positions with 0xff, which rejects for i below 255.
    # The guard bit permits subtraction without borrowing across bytes.
    # Keeping it set in both x and the difference marks each x above i.
    padded = asm('OP_DUP OP_4 OP_PICK OP_CAT') + width + asm('OP_SPLIT OP_DROP')
    test = asm('OP_DUP OP_7 OP_PICK OP_OR') + _UNSIGNED
    accepted_mask = fit + asm('OP_AND OP_6 OP_PICK OP_AND OP_6 OP_PICK OP_XOR OP_1 OP_RSHIFT')
    # Indicators are now 0x40 so their high bit cannot become a numeric sign.
    if find_by_borrow:
        # XORing x with x-1 leaves 0xff in every byte below the first hit,
        # 0x7f at the hit and zero above it. Its minimal size is index + 1.
        search = asm('OP_DUP OP_BIN2NUM OP_DUP OP_0NOTEQUAL OP_VERIFY OP_1SUB')
        search += width + asm('OP_NUM2BIN OP_XOR OP_BIN2NUM OP_SIZE OP_NIP OP_1SUB')
    else:
        search = asm('OP_DUP OP_BIN2NUM OP_0NOTEQUAL OP_VERIFY OP_0 OP_SWAP')
        for level in reversed(range(DEGREE.bit_length() - 1)):
            half = number(1 << level)
            search += half + asm('OP_SPLIT OP_SWAP OP_DUP OP_BIN2NUM OP_0NOTEQUAL OP_IF OP_NIP')
            search += asm('OP_ELSE OP_DROP OP_SWAP') + half + asm('OP_ADD OP_SWAP OP_ENDIF')
        search += asm('OP_DROP')

    # Consume up to and including the first acceptable byte. The last
    # selection accepts every byte, but still requires a remaining draw.
    read = asm('OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP') + _UNSIGNED
    replace = _replace_lane(asm('OP_1'), b'')
    get_entry = asm('OP_SWAP OP_TOALTSTACK OP_2DUP OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_DROP')
    save_entry = asm('OP_TOALTSTACK OP_SWAP')
    set_sign = asm('OP_SWAP OP_2 OP_PICK OP_2 OP_MOD OP_IF OP_1NEGATE OP_ELSE OP_1 OP_ENDIF OP_1 OP_NUM2BIN')
    advance = asm('OP_SWAP OP_2 OP_DIV OP_SWAP OP_FROMALTSTACK')
    for i in range(first, DEGREE):
        if i == DEGREE - 1:
            code += asm('OP_0')
        else:
            threshold = number(i - 127) + asm('OP_7 OP_PICK OP_MUL OP_SUB')
            code += padded + test + threshold + accepted_mask + search
        code += read + get_entry + save_entry + number(i) + asm('OP_FROMALTSTACK') + replace
        code += set_sign + replace + advance
    return code + asm('OP_DROP OP_TOALTSTACK OP_2DROP OP_2DROP OP_FROMALTSTACK')


@cache
def sample_in_ball_script(*, compact=True, optimize=True, packed_rows=True, packed_state=True,
                          stream_rows=True, vector_bytes=False, direct_absorb=False, signed=False,
                          search=False, find_by_borrow=False):
    """Replace c-tilde32 with the packed coefficients of c."""
    shake = shake256_script(CHALLENGE_BYTES, SAMPLE_IN_BALL_BYTES, compact=compact, optimize=optimize,
                            packed_rows=packed_rows, packed_state=packed_state, stream_rows=stream_rows,
                            vector_bytes=vector_bytes, direct_absorb=direct_absorb)
    return shake + sample_from_stream_script(signed=signed, search=search, find_by_borrow=find_by_borrow)

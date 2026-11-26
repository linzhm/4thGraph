"""ML-DSA-44 SampleInBall with an explicit Script XOF budget."""

from functools import cache

from fips204 import CHALLENGE_BYTES, CHALLENGE_SIGN_BYTES, CHALLENGE_WEIGHT, SAMPLE_IN_BALL_BYTES
from shake_script import shake256_script
from fourthgraph.bsv.script import asm, number, push
from polynomial import DEGREE, MODULUS

_COEFFICIENT_BYTES = 3


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
def sample_from_stream_script(*, signed=False):
    """Decode a SHAKE256 prefix into three-byte residues or one-byte signed coefficients."""
    width = 1 if signed else _COEFFICIENT_BYTES
    shape = asm('OP_SIZE') + number(SAMPLE_IN_BALL_BYTES) + asm('OP_NUMEQUALVERIFY')
    shape += number(CHALLENGE_SIGN_BYTES) + asm('OP_SPLIT OP_SWAP')
    shape += push(b'\x00') + asm('OP_CAT OP_BIN2NUM OP_0')
    shape += number(DEGREE * width) + asm('OP_NUM2BIN') + number(DEGREE - CHALLENGE_WEIGHT)
    draws = _sample_byte(width, signed=signed) * (SAMPLE_IN_BALL_BYTES - CHALLENGE_SIGN_BYTES)
    # Discard all sampler state before returning the one exhaustion error.
    end = number(DEGREE) + asm('OP_NUMEQUAL OP_IF OP_NIP OP_NIP '
                               'OP_ELSE OP_2DROP OP_DROP OP_0 OP_VERIFY OP_ENDIF')
    return shape + draws + end


@cache
def sample_in_ball_script(*, compact=True, optimize=True, packed_rows=True, packed_state=True,
                          stream_rows=True, signed=False):
    """Replace c-tilde32 with the packed coefficients of c."""
    shake = shake256_script(CHALLENGE_BYTES, SAMPLE_IN_BALL_BYTES, compact=compact, optimize=optimize,
                            packed_rows=packed_rows, packed_state=packed_state, stream_rows=stream_rows)
    return shake + sample_from_stream_script(signed=signed)

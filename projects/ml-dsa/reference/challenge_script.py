"""ML-DSA-44 SampleInBall with an explicit Script XOF budget."""

from functools import cache

from shake_script import shake256_script
from shared.script import asm, number, push
from polynomial import DEGREE, MODULUS

_COEFFICIENT_BYTES = 3
_POLYNOMIAL_BYTES = DEGREE * _COEFFICIENT_BYTES
_TAU = 39
_SIGN_BYTES = 8
DEFAULT_STREAM_BYTES = 136


def _replace_lane():
    # Suffix P, index, replacement -> P with that lane replaced.
    return asm('OP_TOALTSTACK OP_3 OP_MUL OP_SPLIT OP_3 OP_SPLIT OP_NIP '
               'OP_FROMALTSTACK OP_SWAP OP_CAT OP_CAT')


def _sample_byte():
    # Entry: remaining stream, sign bits, polynomial, next index.
    code = asm('OP_DUP') + number(DEGREE) + asm('OP_LESSTHAN OP_IF')
    code += asm('OP_3 OP_ROLL OP_1 OP_SPLIT OP_SWAP') + push(b'\x00')
    code += asm('OP_CAT OP_BIN2NUM OP_TOALTSTACK OP_2SWAP OP_3 OP_ROLL OP_FROMALTSTACK')
    # The candidate is accepted only when it is no greater than i.
    code += asm('OP_2DUP OP_LESSTHAN OP_NOTIF')
    code += asm('OP_2 OP_PICK OP_OVER OP_3 OP_MUL OP_SPLIT OP_NIP OP_3 OP_SPLIT OP_DROP')
    # Copy P[j] into P[i] before replacing P[j].
    code += asm('OP_TOALTSTACK OP_2 OP_PICK OP_2 OP_PICK OP_FROMALTSTACK') + _replace_lane()
    code += asm('OP_3 OP_ROLL OP_DROP OP_2 OP_ROLL OP_TOALTSTACK OP_SWAP')
    code += asm('OP_2 OP_PICK OP_2 OP_MOD OP_IF') + number(MODULUS - 1)
    code += asm('OP_ELSE OP_1 OP_ENDIF OP_3 OP_NUM2BIN') + _replace_lane()
    code += asm('OP_SWAP OP_2 OP_DIV OP_SWAP OP_FROMALTSTACK OP_1ADD')
    return code + asm('OP_ELSE OP_DROP OP_ENDIF OP_ENDIF')


@cache
def sample_from_stream_script(stream_bytes=DEFAULT_STREAM_BYTES):
    """Decode a fixed-size SHAKE256 prefix into canonical c coefficients."""
    if type(stream_bytes) is not int or stream_bytes < _SIGN_BYTES + _TAU:
        raise ValueError('the XOF budget must hold the sign bits and 39 draws')
    shape = asm('OP_SIZE') + number(stream_bytes) + asm('OP_NUMEQUALVERIFY OP_8 OP_SPLIT OP_SWAP')
    shape += push(b'\x00') + asm('OP_CAT OP_BIN2NUM OP_0')
    shape += number(_POLYNOMIAL_BYTES) + asm('OP_NUM2BIN') + number(DEGREE - _TAU)
    draws = _sample_byte() * (stream_bytes - _SIGN_BYTES)
    # FIPS 204 continues reading on rejection. The bounded Script can only
    # succeed if the entire challenge was constructed within its XOF prefix.
    return shape + draws + number(DEGREE) + asm('OP_NUMEQUALVERIFY OP_NIP OP_NIP')


@cache
def sample_in_ball_script(stream_bytes=DEFAULT_STREAM_BYTES):
    """Replace c-tilde32 with c packed as 256 three-byte LE residues."""
    return shake256_script(32, stream_bytes) + sample_from_stream_script(stream_bytes)

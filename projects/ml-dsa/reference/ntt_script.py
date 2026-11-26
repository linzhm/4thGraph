"""Script kernels for NTT arithmetic over the FIPS 204 ML-DSA ring.

These kernels accept public arithmetic data. They are not payment locks.
"""

from functools import cache
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from fourthgraph.bsv.script import asm, number
from fips204 import verification_key_rows
from polynomial import DEGREE, MODULUS, twiddle

COEFFICIENT_BYTES = 3
POLYNOMIAL_BYTES = DEGREE * COEFFICIENT_BYTES

_Q = number(MODULUS)
_COEFF = number(COEFFICIENT_BYTES)
_REDUCE = _Q + asm("OP_MOD")
_NORMALIZE = asm("OP_DUP OP_0 OP_LESSTHAN OP_IF") + _Q + asm("OP_ADD OP_ENDIF")
_ROLL_TOP = (b"", asm("OP_SWAP"), asm("OP_ROT"))
_SPLIT_COEFFICIENT = _COEFF + asm("OP_SPLIT OP_SWAP")


def _take(order, index, *, above=0, compact=False):
    position = order.index(index)
    depth = len(order) - position - 1 + above
    order.pop(position)
    if compact and depth < len(_ROLL_TOP):
        return _ROLL_TOP[depth]
    return number(depth) + asm("OP_ROLL")


def _unpack(*, trusted=False):
    """Replace a 768-byte item with canonical coefficients, a[255] on top."""
    if trusted:
        return (_SPLIT_COEFFICIENT + asm("OP_BIN2NUM OP_SWAP")) * DEGREE + asm("OP_DROP")
    code = bytearray(asm("OP_SIZE") + number(POLYNOMIAL_BYTES) + asm("OP_NUMEQUALVERIFY"))
    coefficient = asm("OP_DUP OP_BIN2NUM OP_DUP") + _COEFF + asm("OP_NUM2BIN OP_ROT OP_EQUALVERIFY")
    coefficient += asm("OP_DUP OP_0") + _Q + asm("OP_WITHIN OP_VERIFY")
    for _ in range(DEGREE):
        code += _COEFF + asm("OP_SPLIT OP_SWAP") + coefficient + asm("OP_SWAP")
    return bytes(code) + asm("OP_DROP")


def _forward_butterfly(twiddle):
    # [a, b] -> [(a-z*b) mod q, (a+z*b) mod q].
    code = number(twiddle) + asm("OP_MUL") + _REDUCE
    code += asm("OP_2DUP OP_ADD") + _REDUCE + asm("OP_TOALTSTACK")
    code += asm("OP_SUB") + _Q + asm("OP_ADD") + _REDUCE
    return code + asm("OP_FROMALTSTACK")


def _inverse_butterfly(twiddle):
    # [a, b] -> [(-z*(a-b)) mod q, (a+b) mod q], with twiddle = -z mod q.
    code = asm("OP_2DUP OP_ADD") + _REDUCE + asm("OP_TOALTSTACK")
    code += asm("OP_SUB") + _Q + asm("OP_ADD")
    code += number(twiddle) + asm("OP_MUL") + _REDUCE
    return code + asm("OP_FROMALTSTACK")


def _signed_forward_butterfly(twiddle):
    # Signed residues keep |coefficient| < q without normalizing after every
    # butterfly. The unreduced product and sum fit below q² (< 2^46).
    code = number(twiddle) + asm("OP_MUL")
    code += asm("OP_2DUP OP_ADD") + _REDUCE + asm("OP_TOALTSTACK")
    return code + asm("OP_SUB") + _REDUCE + asm("OP_FROMALTSTACK")


def _signed_inverse_butterfly(twiddle):
    code = asm("OP_2DUP OP_ADD") + _REDUCE + asm("OP_TOALTSTACK")
    code += asm("OP_SUB") + number(twiddle) + asm("OP_MUL") + _REDUCE
    return code + asm("OP_FROMALTSTACK")


def _compact_butterfly(zeta, *, inverse):
    # Reduce at serialization. All eight stages grow magnitudes by at most
    # 2q each, so even after inverse scaling they fit in 30 ScriptNum bytes.
    signed_zeta = zeta - MODULUS if zeta > MODULUS // 2 else zeta
    multiply = number(signed_zeta) + asm("OP_MUL")
    butterfly = asm("OP_2DUP OP_ADD OP_TOALTSTACK OP_SUB")
    return (butterfly + multiply if inverse else multiply + butterfly) + asm("OP_FROMALTSTACK")


def transform_script(*, inverse=False, signed_residues=False, compact=False):
    """Replace the top canonical polynomial with its FIPS 204 NTT or INTT."""
    return _transform(inverse=inverse, signed_residues=signed_residues, compact=compact)


@cache
def _transform(*, inverse, signed_residues=False, compact=False, trusted=False):
    code = bytearray(_unpack(trusted=trusted))
    order = list(range(DEGREE))
    log_degree = DEGREE.bit_length() - 1
    if inverse:
        stages = range(log_degree)
        next_twiddle = DEGREE
        butterfly = _signed_inverse_butterfly if signed_residues else _inverse_butterfly
    else:
        stages = reversed(range(log_degree))
        next_twiddle = 0
        butterfly = _signed_forward_butterfly if signed_residues else _forward_butterfly
    for stage in stages:
        width = 1 << stage
        for start in range(0, DEGREE, 2 * width):
            next_twiddle += -1 if inverse else 1
            zeta = twiddle(next_twiddle)
            if inverse:
                zeta = MODULUS - zeta
            operations = _compact_butterfly(zeta, inverse=inverse) if compact else butterfly(zeta)
            for left in range(start, start + width):
                right = left + width
                code += _take(order, left, compact=compact)
                code += _take(order, right, above=1, compact=compact) + operations
                order.extend((right, left))

    scale = number(pow(DEGREE, -1, MODULUS)) + asm("OP_MUL") + _REDUCE if inverse else b""
    if compact:
        code += asm("OP_0")
        for index in range(DEGREE):
            code += _take(order, index, above=1, compact=True)
            code += (scale if inverse else _REDUCE) + _NORMALIZE + _COEFF + asm("OP_NUM2BIN OP_CAT")
        return bytes(code)

    # Reserve the result on the altstack while the last coefficients are rolled.
    normalize = _NORMALIZE if signed_residues else b""
    code += asm("OP_0 OP_TOALTSTACK")
    for index in range(DEGREE):
        code += _take(order, index) + scale + normalize + _COEFF + asm("OP_NUM2BIN")
        code += asm("OP_FROMALTSTACK OP_SWAP OP_CAT OP_TOALTSTACK")
    return bytes(code) + asm("OP_FROMALTSTACK")


@cache
def ring_product_script():
    """Replace two canonical polynomials with their product in Z_q[X]/(X^256+1)."""
    forward = transform_script()
    code = bytearray(forward + asm("OP_SWAP") + forward)
    split = _COEFF + asm("OP_SPLIT OP_SWAP OP_BIN2NUM")
    product = split + asm("OP_TOALTSTACK OP_SWAP") + split
    product += asm("OP_FROMALTSTACK OP_MUL") + _REDUCE + _COEFF + asm("OP_NUM2BIN")
    code += (product + asm("OP_TOALTSTACK OP_SWAP")) * DEGREE
    code += asm("OP_2DROP OP_0")
    code += asm("OP_FROMALTSTACK OP_SWAP OP_CAT") * DEGREE
    return bytes(code) + transform_script(inverse=True)


def verification_equation_script(public_key, *, signed_residues=False, compact=False):
    """Evaluate the fixed-key verification equation on already-decoded polynomials.

    Input is one packed item containing c, z[0], ..., z[3] in canonical
    coefficient form. Output contains the four reconstructed rows. Signature
    decoding, the challenge, the z norm, and hint use remain caller checks.
    """
    rows = list(verification_key_rows(public_key))
    if compact:
        return _compact_equation(rows)
    input_count = len(rows[0])
    code = bytearray(asm("OP_SIZE") + number(input_count * POLYNOMIAL_BYTES) + asm("OP_NUMEQUALVERIFY"))
    split_polynomial = number(POLYNOMIAL_BYTES) + asm("OP_SPLIT OP_SWAP")
    code += (split_polynomial + transform_script(signed_residues=signed_residues) + asm("OP_TOALTSTACK")) * input_count
    code += asm("OP_DROP OP_0") + asm("OP_FROMALTSTACK OP_SWAP OP_CAT") * input_count

    for row in rows:
        code += asm("OP_0")
        for coefficient in range(DEGREE):
            code += asm("OP_0")  # Sum of the five NTT-domain products.
            for column, fixed in enumerate(row):
                offset = column * POLYNOMIAL_BYTES + coefficient * COEFFICIENT_BYTES
                code += asm("OP_2 OP_PICK") + number(offset) + asm("OP_SPLIT OP_NIP")
                code += _COEFF + asm("OP_SPLIT OP_DROP OP_BIN2NUM")
                code += number(fixed[coefficient]) + asm("OP_MUL OP_ADD")
            code += _REDUCE + _COEFF + asm("OP_NUM2BIN OP_CAT")
        code += transform_script(inverse=True, signed_residues=signed_residues) + asm("OP_TOALTSTACK")

    code += asm("OP_DROP OP_0") + asm("OP_FROMALTSTACK OP_SWAP OP_CAT") * len(rows)
    return bytes(code)


def _compact_equation(rows):
    input_count, row_count = len(rows[0]), len(rows)
    code = bytearray(asm("OP_SIZE") + number(input_count * POLYNOMIAL_BYTES) + asm("OP_NUMEQUALVERIFY"))
    split_polynomial = number(POLYNOMIAL_BYTES) + asm("OP_SPLIT OP_SWAP")
    code += (split_polynomial + transform_script(compact=True) + asm("OP_TOALTSTACK")) * input_count
    code += asm("OP_DROP") + asm("OP_FROMALTSTACK") * input_count + asm("OP_0") * row_count

    # The stack holds the five polynomial tails followed by the four row
    # buffers. Read each column's next coefficient once for all four rows.
    read = number(input_count + row_count - 1) + asm("OP_ROLL")
    read += _SPLIT_COEFFICIENT + asm("OP_BIN2NUM OP_TOALTSTACK")
    read = read * input_count + asm("OP_FROMALTSTACK") * input_count
    pack_coefficient = _REDUCE + _COEFF + asm("OP_NUM2BIN")
    for coefficient in range(DEGREE):
        code += read
        for row_index, row in enumerate(reversed(rows)):
            last_row = row_index == row_count - 1
            for column, values in enumerate(reversed(row)):
                if last_row:
                    code += asm("OP_SWAP") if column else b""
                else:
                    code += number(column + 1) + asm("OP_PICK") if column else asm("OP_DUP")
                code += number(values[coefficient]) + asm("OP_MUL")
                if column:
                    code += asm("OP_ADD")
            code += pack_coefficient
            depth = (input_count if last_row else 2 * input_count) + 1
            code += number(depth) + asm("OP_ROLL OP_SWAP OP_CAT OP_TOALTSTACK")
        code += asm("OP_FROMALTSTACK") * row_count
    inverse = _transform(inverse=True, compact=True, trusted=True)
    code += (inverse + asm("OP_TOALTSTACK")) * row_count
    code += asm("OP_2DROP") * (input_count // 2) + asm("OP_DROP") * (input_count % 2)
    return bytes(code) + asm("OP_FROMALTSTACK") + asm("OP_FROMALTSTACK OP_CAT") * (row_count - 1)

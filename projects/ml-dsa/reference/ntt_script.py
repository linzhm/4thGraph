"""Script kernels for NTT arithmetic over the FIPS 204 ML-DSA ring.

These kernels accept public arithmetic data. They are not payment locks.
"""

from functools import cache
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from fourthgraph.bsv.script import asm, number, push
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
_INVERSE_SCALE = pow(DEGREE, -1, MODULUS)
_LANE_BYTES = 26
_LANE_RADIX = 1 << (8 * _LANE_BYTES)
# Each centered butterfly grows a lane by at most q. Starting below q,
# all eight stages stay below q**9, which fits on either side of this offset.
# The offset is a multiple of q, so decoding biased lanes preserves residues.
_LANE_OFFSET = (_LANE_RADIX // 2 // MODULUS) * MODULUS
_READ_LANE = number(_LANE_BYTES) + asm("OP_SPLIT OP_SWAP") + push(b"\x00") + asm("OP_CAT OP_BIN2NUM")


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


def _butterflies(order, *, inverse, signed_residues=False, compact=False):
    code = bytearray()
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
    return code


@cache
def _transform(*, inverse, signed_residues=False, compact=False, trusted=False):
    code = bytearray(_unpack(trusted=trusted))
    order = list(range(DEGREE))
    code += _butterflies(order, inverse=inverse, signed_residues=signed_residues, compact=compact)

    scale = number(_INVERSE_SCALE) + asm("OP_MUL") + _REDUCE if inverse else b""
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


def checked_equation_script(public_key, *, packed=True):
    """Reconstruct rows from the sampler and the range-checked signed response."""
    # The inverse transform is linear. Fold its 1/256 factor into the public
    # coefficients so each unpacked output lane needs only reduction mod q.
    rows = [
        [tuple(value * _INVERSE_SCALE % MODULUS for value in column) for column in row]
        for row in verification_key_rows(public_key)
    ]
    return _packed_equation(rows) if packed else _compact_equation(rows, integrated=True)


def _compact_equation(rows, *, integrated=False):
    input_count, row_count = len(rows[0]), len(rows)
    code = bytearray(asm("OP_SIZE") + number(input_count * POLYNOMIAL_BYTES) + asm("OP_NUMEQUALVERIFY"))
    split_polynomial = number(POLYNOMIAL_BYTES) + asm("OP_SPLIT OP_SWAP")
    forward = _transform(inverse=False, compact=True, trusted=integrated)
    code += (split_polynomial + forward + asm("OP_TOALTSTACK")) * input_count
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
            code += _dot_product(reversed(row), coefficient, consume=last_row)
            code += pack_coefficient
            depth = (input_count if last_row else 2 * input_count) + 1
            code += number(depth) + asm("OP_ROLL OP_SWAP OP_CAT OP_TOALTSTACK")
        code += asm("OP_FROMALTSTACK") * row_count
    drop_tails = asm("OP_2DROP") * (input_count // 2) + asm("OP_DROP") * (input_count % 2)
    if integrated:
        code += asm("OP_CAT") * (row_count - 1) + asm("OP_TOALTSTACK")
        return bytes(code) + drop_tails + asm("OP_FROMALTSTACK") + _packed_inverse()
    inverse = _transform(inverse=True, compact=True, trusted=True)
    code += (inverse + asm("OP_TOALTSTACK")) * row_count + drop_tails
    return bytes(code) + asm("OP_FROMALTSTACK") + asm("OP_FROMALTSTACK OP_CAT") * (row_count - 1)


def _dot_product(columns, coefficient, *, consume):
    """Apply fixed coefficients to NTT values ordered from the top down."""
    code = bytearray()
    for column, values in enumerate(columns):
        if consume:
            code += asm("OP_SWAP") if column else b""
        else:
            code += number(column + 1) + asm("OP_PICK") if column else asm("OP_DUP")
        code += number(values[coefficient]) + asm("OP_MUL")
        if column:
            code += asm("OP_ADD")
    return code


def _packed_bias(lanes, offset):
    return number(offset * sum(_LANE_RADIX ** index for index in range(lanes)))


def _packed_equation(rows):
    input_count, row_count = len(rows[0]), len(rows)
    code = bytearray(asm("OP_SIZE") + number(input_count * POLYNOMIAL_BYTES) + asm("OP_NUMEQUALVERIFY"))
    code += asm("OP_TOALTSTACK") + number(_LANE_RADIX) + _packed_bias(input_count, _LANE_OFFSET)
    code += asm("OP_FROMALTSTACK")
    code += (number(POLYNOMIAL_BYTES) + asm("OP_SPLIT")) * (input_count - 1)

    # The packed challenge and signed responses were checked upstream. Read
    # each coefficient across the five polynomial tails in Horner order.
    read = _SPLIT_COEFFICIENT + asm("OP_BIN2NUM")
    first = number(input_count - 1) + asm("OP_ROLL") + read
    next_lane = number(input_count + 2) + asm("OP_PICK OP_MUL")
    next_lane += number(input_count) + asm("OP_ROLL") + read + asm("OP_ROT OP_ADD")
    code += (first + next_lane * (input_count - 1) + asm("OP_TOALTSTACK")) * DEGREE
    code += asm("OP_2DROP") * (input_count // 2) + asm("OP_DROP") * (input_count % 2)
    restore = asm("OP_FROMALTSTACK") * DEGREE
    code += restore

    order = list(reversed(range(DEGREE)))
    code += _butterflies(order, inverse=False, compact=True)
    for coefficient in range(DEGREE):
        code += _take(order, coefficient, compact=True)
        code += number(len(order) + 1) + asm("OP_PICK OP_ADD")
        code += number(_LANE_BYTES * input_count + 1) + asm("OP_NUM2BIN")
        # The biased values are congruent to the forward NTT values mod q.
        # Reduce each row of the dot product before packing its inverse input.
        code += (_READ_LANE + asm("OP_SWAP")) * input_count + asm("OP_DROP")
        for row_index, row in enumerate(rows):
            code += _dot_product(row, coefficient, consume=row_index == row_count - 1)
            code += _REDUCE + asm("OP_TOALTSTACK")
        multiply = number(len(order) + 2) + asm("OP_PICK OP_MUL")
        code += asm("OP_FROMALTSTACK")
        code += (multiply + asm("OP_FROMALTSTACK OP_ADD")) * (row_count - 1)
        code += asm("OP_TOALTSTACK")

    # All forward coefficients have been consumed. The altstack holds one
    # packed coefficient per inverse butterfly input, with row zero low.
    code += asm("OP_2DROP") + _packed_bias(row_count, _LANE_OFFSET) + restore
    order = list(reversed(range(DEGREE)))
    code += _butterflies(order, inverse=True, compact=True)
    return bytes(code) + _serialize_inverse_rows(order, row_count)


@cache
def _packed_inverse():
    """Apply the inverse butterflies to all four already scaled rows together."""
    lanes = 4
    half = _LANE_RADIX // 2
    code = bytearray(asm("OP_TOALTSTACK") + _packed_bias(lanes, half) + number(half) + asm("OP_FROMALTSTACK"))
    code += (number(POLYNOMIAL_BYTES) + asm("OP_SPLIT")) * (lanes - 1)
    read = asm("OP_3 OP_ROLL") + _SPLIT_COEFFICIENT
    read += asm("OP_BIN2NUM") + number(_LANE_BYTES) + asm("OP_NUM2BIN OP_TOALTSTACK")
    pack = asm("OP_FROMALTSTACK") + asm("OP_FROMALTSTACK OP_SWAP OP_CAT") * (lanes - 1)
    code += (read * lanes + pack + asm("OP_BIN2NUM OP_TOALTSTACK")) * DEGREE
    code += asm("OP_2DROP OP_2DROP") + asm("OP_FROMALTSTACK") * DEGREE

    order = list(reversed(range(DEGREE)))
    code += _butterflies(order, inverse=True, compact=True)
    return bytes(code) + _serialize_inverse_rows(order, lanes, unbias=True)


def _serialize_inverse_rows(order, lanes, *, unbias=False):
    code = bytearray(asm("OP_0") * lanes)
    for index in range(DEGREE):
        code += _take(order, index, above=lanes, compact=True)
        depth = number(len(order) + lanes + 1 + int(unbias)) + asm("OP_PICK")
        code += depth + asm("OP_ADD") + number(_LANE_BYTES * lanes + 1) + asm("OP_NUM2BIN")
        residue = depth + asm("OP_SUB") + _REDUCE + _NORMALIZE if unbias else _REDUCE
        append = _COEFF + asm("OP_NUM2BIN") + number(lanes + 1) + asm("OP_ROLL OP_SWAP OP_CAT OP_SWAP")
        code += (_READ_LANE + residue + append) * lanes + asm("OP_DROP")
    return bytes(code) + asm("OP_CAT") * (lanes - 1) + asm("OP_NIP") * (1 + int(unbias))

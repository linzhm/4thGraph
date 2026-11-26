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
_SPLIT_LANE = number(_LANE_BYTES) + asm("OP_SPLIT OP_SWAP")
_READ_LANE = _SPLIT_LANE + push(b"\x00") + asm("OP_CAT OP_BIN2NUM")
_READ_POSITIVE_LANE = _SPLIT_LANE + asm("OP_BIN2NUM")


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


def _centered_twiddle(zeta):
    return zeta - MODULUS if zeta > MODULUS // 2 else zeta


def _compact_butterfly(zeta, *, inverse):
    # Reduce at serialization. All eight stages grow magnitudes by at most
    # 2q each, so even after inverse scaling they fit in 30 ScriptNum bytes.
    multiply = number(_centered_twiddle(zeta)) + asm("OP_MUL")
    butterfly = asm("OP_2DUP OP_ADD OP_TOALTSTACK OP_SUB")
    return (butterfly + multiply if inverse else multiply + butterfly) + asm("OP_FROMALTSTACK")


def transform_script(*, inverse=False, signed_residues=False, compact=False):
    """Replace the top canonical polynomial with its FIPS 204 NTT or INTT."""
    return _transform(inverse=inverse, signed_residues=signed_residues, compact=compact)


@cache
def _transform_stages(*, inverse):
    stages = range(DEGREE.bit_length() - 1)
    index = DEGREE if inverse else 0
    layers = []
    if not inverse:
        stages = reversed(stages)
    for stage in stages:
        width = 1 << stage
        factors = []
        for _ in range(DEGREE // (2 * width)):
            index += -1 if inverse else 1
            zeta = twiddle(index)
            factors.append(MODULUS - zeta if inverse else zeta)
        layers.append((width, tuple(factors)))
    return tuple(layers)


def _butterflies(order, *, inverse, signed_residues=False, compact=False):
    code = bytearray()
    if inverse:
        butterfly = _signed_inverse_butterfly if signed_residues else _inverse_butterfly
    else:
        butterfly = _signed_forward_butterfly if signed_residues else _forward_butterfly
    for width, factors in _transform_stages(inverse=inverse):
        for group, zeta in enumerate(factors):
            start = group * 2 * width
            operations = _compact_butterfly(zeta, inverse=inverse) if compact else butterfly(zeta)
            for left in range(start, start + width):
                right = left + width
                code += _take(order, left, compact=compact)
                code += _take(order, right, above=1, compact=compact) + operations
                order.extend((right, left))
    return code


def _paired_butterflies(order, *, inverse):
    """Evaluate two dependent layers while each four-coefficient group is on top."""
    code = bytearray()
    layers = _transform_stages(inverse=inverse)
    for (first_width, first), (second_width, second) in zip(layers[::2], layers[1::2], strict=True):
        width = min(first_width, second_width)
        for group, start in enumerate(range(0, DEGREE, 4 * width)):
            if inverse:
                first_pair, second_pair = first[2 * group:2 * group + 2], (second[group],) * 2
            else:
                first_pair, second_pair = (first[group],) * 2, second[2 * group:2 * group + 2]
            first_left, first_right = (_compact_butterfly(zeta, inverse=inverse) for zeta in first_pair)
            second_left, second_right = (_compact_butterfly(zeta, inverse=inverse) for zeta in second_pair)
            # Staged as [a, b, c, d]. First combine (c, d) and (a, b),
            # then (a, c) and (b, d), leaving [c, a, d, b].
            block = first_right + asm("OP_2SWAP") + first_left
            block += asm("OP_ROT") + second_left + asm("OP_2SWAP OP_SWAP") + second_right
            for a in range(start, start + width):
                b, c, d = a + first_width, a + second_width, a + 3 * width
                for above, index in enumerate((a, b, c, d)):
                    code += _take(order, index, above=above, compact=True)
                code += block
                order.extend((c, a, d, b))
    return code


@cache
def _positive_lane_offset():
    # Propagate absolute bounds through the same centered butterflies as the
    # emitted code. Adding the offset changes none of the residues mod q.
    maximum = 0
    for inverse in (False, True):
        bounds = [MODULUS - 1] * DEGREE
        for width, factors in _transform_stages(inverse=inverse):
            for group, zeta in enumerate(factors):
                start = group * 2 * width
                factor = abs(_centered_twiddle(zeta))
                for left in range(start, start + width):
                    right = left + width
                    a, b = bounds[left], bounds[right]
                    if inverse:
                        bounds[left], bounds[right] = a + b, (a + b) * factor
                    else:
                        bounds[left] = bounds[right] = a + b * factor
        maximum = max(maximum, max(bounds))
    offset = (maximum // MODULUS + 1) * MODULUS
    # The top bit of every lane stays clear, including the high lane of the
    # whole packed integer, so the serialized values need no sign byte.
    assert maximum + offset < _LANE_RADIX // 2
    return offset


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


def checked_equation_script(public_key, *, packed=True, paired=True, signed_challenge=False):
    """Reconstruct rows from the sampler and the range-checked signed response."""
    # The inverse transform is linear. Fold its 1/256 factor into the public
    # coefficients so each unpacked output lane needs only reduction mod q.
    rows = [
        [tuple(value * _INVERSE_SCALE % MODULUS for value in column) for column in row]
        for row in verification_key_rows(public_key)
    ]
    if packed:
        return _packed_equation(rows, paired=paired, signed_challenge=signed_challenge)
    return _compact_equation(rows, integrated=True)


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


def _packed_equation(rows, *, paired, signed_challenge):
    input_count, row_count = len(rows[0]), len(rows)
    offset = _positive_lane_offset() if paired else _LANE_OFFSET
    read_lane = _READ_POSITIVE_LANE if paired else _READ_LANE
    extra_byte = 0 if paired else 1
    challenge_bytes = DEGREE if signed_challenge else POLYNOMIAL_BYTES
    code = bytearray(asm("OP_SIZE") + number(challenge_bytes + (input_count - 1) * POLYNOMIAL_BYTES)
                     + asm("OP_NUMEQUALVERIFY"))
    code += asm("OP_TOALTSTACK") + number(_LANE_RADIX) + _packed_bias(input_count, offset)
    code += asm("OP_FROMALTSTACK")
    code += number(challenge_bytes) + asm("OP_SPLIT")
    code += (number(POLYNOMIAL_BYTES) + asm("OP_SPLIT")) * (input_count - 2)

    # The packed challenge and signed responses were checked upstream. Read
    # each coefficient across the five polynomial tails in Horner order.
    read = _SPLIT_COEFFICIENT + asm("OP_BIN2NUM")
    challenge_read = asm("OP_1 OP_SPLIT OP_SWAP OP_BIN2NUM") if signed_challenge else read
    first = number(input_count - 1) + asm("OP_ROLL") + challenge_read
    next_lane = number(input_count + 2) + asm("OP_PICK OP_MUL")
    next_lane += number(input_count) + asm("OP_ROLL") + read + asm("OP_ROT OP_ADD")
    code += (first + next_lane * (input_count - 1) + asm("OP_TOALTSTACK")) * DEGREE
    code += asm("OP_2DROP") * (input_count // 2) + asm("OP_DROP") * (input_count % 2)
    restore = asm("OP_FROMALTSTACK") * DEGREE
    code += restore

    order = list(reversed(range(DEGREE)))
    code += (_paired_butterflies(order, inverse=False) if paired
             else _butterflies(order, inverse=False, compact=True))
    for coefficient in range(DEGREE):
        code += _take(order, coefficient, compact=True)
        code += number(len(order) + 1) + asm("OP_PICK OP_ADD")
        code += number(_LANE_BYTES * input_count + extra_byte) + asm("OP_NUM2BIN")
        # The biased values are congruent to the forward NTT values mod q.
        # Reduce each row of the dot product before packing its inverse input.
        code += (read_lane + asm("OP_SWAP")) * input_count + asm("OP_DROP")
        for row_index, row in enumerate(rows):
            code += _dot_product(row, coefficient, consume=row_index == row_count - 1)
            code += _REDUCE + asm("OP_TOALTSTACK")
        multiply = number(len(order) + 2) + asm("OP_PICK OP_MUL")
        code += asm("OP_FROMALTSTACK")
        code += (multiply + asm("OP_FROMALTSTACK OP_ADD")) * (row_count - 1)
        code += asm("OP_TOALTSTACK")

    # All forward coefficients have been consumed. The altstack holds one
    # packed coefficient per inverse butterfly input, with row zero low.
    code += asm("OP_2DROP") + _packed_bias(row_count, offset) + restore
    order = list(reversed(range(DEGREE)))
    code += (_paired_butterflies(order, inverse=True) if paired
             else _butterflies(order, inverse=True, compact=True))
    return bytes(code) + _serialize_inverse_rows(order, row_count, positive=paired)


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


def _serialize_inverse_rows(order, lanes, *, unbias=False, positive=False):
    read_lane = _READ_POSITIVE_LANE if positive else _READ_LANE
    code = bytearray(asm("OP_0") * lanes)
    for index in range(DEGREE):
        code += _take(order, index, above=lanes, compact=True)
        depth = number(len(order) + lanes + 1 + int(unbias)) + asm("OP_PICK")
        width = _LANE_BYTES * lanes + (0 if positive else 1)
        code += depth + asm("OP_ADD") + number(width) + asm("OP_NUM2BIN")
        residue = depth + asm("OP_SUB") + _REDUCE + _NORMALIZE if unbias else _REDUCE
        append = _COEFF + asm("OP_NUM2BIN") + number(lanes + 1) + asm("OP_ROLL OP_SWAP OP_CAT OP_SWAP")
        code += (read_lane + residue + append) * lanes + asm("OP_DROP")
    return bytes(code) + asm("OP_CAT") * (lanes - 1) + asm("OP_NIP") * (1 + int(unbias))

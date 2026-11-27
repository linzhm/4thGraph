"""Fixed-length FIPS 202 SHAKE128 and SHAKE256 bytecode for Bitcoin Script.

The permutation uses Genesis byte-vector shifts, XOR, AND and INVERT on
eight-byte lanes and five-lane rows. Lengths are fixed at generation time.
"""

from functools import cache
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from fourthgraph.bsv.script import asm, number, push


_LANE_BYTES = 8
_ROW_BYTES = 5 * _LANE_BYTES
_STATE_BYTES = 5 * _ROW_BYTES
_LANE_LSB_MASK = (bytes(_LANE_BYTES - 1) + b'\x01') * 5
_POSITIONS = tuple((x, y) for y in range(5) for x in range(5))

# Indexed by x, then y. FIPS 202 Algorithms 2–7 and Table 2.
_ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_PI_SOURCES = {(y, (2 * x + 3 * y) % 5): (x, y) for x, y in _POSITIONS}
_PICK_TOP = (asm('OP_DUP'), asm('OP_OVER'))
_ROLL_TOP = (b'', asm('OP_SWAP'), asm('OP_ROT'))
_REVERSE_LANE = (
    asm('OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK') * (_LANE_BYTES - 1)
    + asm('OP_FROMALTSTACK OP_CAT') * (_LANE_BYTES - 1)
)
_PACK_ROW = asm('OP_CAT') * 4
_SPLIT_ROW = asm('OP_8 OP_SPLIT') * 4
_UNPACK_ROWS = _SPLIT_ROW + (asm('OP_FROMALTSTACK') + _SPLIT_ROW) * 4


def _rotate_left(bits):
    if bits == 0:
        return b''
    return (
        asm('OP_DUP') + number(bits) + asm('OP_LSHIFT OP_SWAP')
        + number(64 - bits) + asm('OP_RSHIFT OP_OR')
    )


def _reverse_bytes(width):
    if width == 1:
        return b''
    half = width // 2
    reverse_half = _reverse_bytes(half)
    return (number(half) + asm('OP_SPLIT') + reverse_half + asm('OP_SWAP')
            + reverse_half + asm('OP_CAT'))


def _rotate_doubled_lane(bits):
    if bits == 0:
        return b''
    # Shifting two copies fills the vacated bits of the first copy.
    return asm('OP_DUP OP_CAT') + number(bits) + asm('OP_LSHIFT OP_8 OP_SPLIT OP_DROP')


def _rotate_bytes(offset):
    return number(offset) + asm('OP_SPLIT OP_SWAP OP_CAT')


def _rotate_packed_lane(bits):
    if bits and bits % 8 == 0:
        return _rotate_bytes(bits // 8)
    return _rotate_doubled_lane(bits)


def _rotate_short_lane(bits):
    if bits > 48 and bits % 8:
        # The final half of a right-shifted double lane is the same rotation.
        return asm('OP_DUP OP_CAT') + number(64 - bits) + asm('OP_RSHIFT OP_8 OP_SPLIT OP_NIP')
    return _rotate_packed_lane(bits)


class _Round:
    """Resolve named lanes to stack offsets while emitting one round."""

    def __init__(self, *, compact, rotate):
        self.code = bytearray()
        self.lanes = [('a', x, y) for x, y in _POSITIONS]
        self.compact = compact
        self.rotate = rotate

    def roll(self, lane):
        position = self.lanes.index(lane)
        depth = len(self.lanes) - 1 - position
        if self.compact and depth < len(_ROLL_TOP):
            self.code += _ROLL_TOP[depth]
        elif depth:
            self.code += number(depth) + asm('OP_ROLL')
        self.lanes.append(self.lanes.pop(position))

    def pick(self, lane, *, last_use=False):
        if self.compact and last_use:
            self.roll(lane)
            return
        depth = len(self.lanes) - 1 - self.lanes.index(lane)
        if self.compact and depth < len(_PICK_TOP):
            self.code += _PICK_TOP[depth]
        else:
            self.code += number(depth) + asm('OP_PICK')
        self.lanes.append(None)

    def drop(self, lane):
        self.roll(lane)
        self.code += asm('OP_DROP')
        self.lanes.pop()

    def binary(self, opcode):
        self.code += asm(opcode)
        self.lanes.pop()
        self.lanes[-1] = None

    def name(self, lane):
        self.lanes[-1] = lane

    def columns(self):
        for x in range(5):
            self.pick(('a', x, 0))
            for y in range(1, 5):
                self.pick(('a', x, y))
                self.binary('OP_XOR')
            self.name(('c', x))
        for x in range(5):
            previous, following = (x - 1) % 5, (x + 1) % 5
            self.pick(('c', previous), last_use=x > (x - 2) % 5)
            self.pick(('c', following), last_use=x > (x + 2) % 5)
            self.code += self.rotate(1)
            self.binary('OP_XOR')
            self.name(('d', x))
        if not self.compact:
            for x in range(5):
                self.drop(('c', x))

    def move_and_rotate(self, *, theta_done=False):
        uses_left = [5] * 5
        for x, y in _POSITIONS:
            source_x, source_y = _PI_SOURCES[x, y]
            self.roll(('a', source_x, source_y))
            if not theta_done:
                uses_left[source_x] -= 1
                self.pick(('d', source_x), last_use=uses_left[source_x] == 0)
                self.binary('OP_XOR')
            self.code += self.rotate(_ROTATION[source_x][source_y])
            self.name(('b', x, y))
        if not self.compact and not theta_done:
            for x in range(5):
                self.drop(('d', x))

    def mix_rows(self, round_constant):
        # b[x] is used by output columns x, x-1 and x-2 within the row.
        last_use = [max(x, (x - 1) % 5, (x - 2) % 5) for x in range(5)]
        for y in range(5):
            for x in range(5):
                following, second = (x + 1) % 5, (x + 2) % 5
                self.pick(('b', following, y), last_use=last_use[following] == x)
                self.code += asm('OP_INVERT')
                self.pick(('b', second, y), last_use=last_use[second] == x)
                self.binary('OP_AND')
                self.pick(('b', x, y), last_use=last_use[x] == x)
                self.binary('OP_XOR')
                if x == y == 0:
                    self.code += push(round_constant.to_bytes(_LANE_BYTES, 'big')) + asm('OP_XOR')
                self.name(('a', x, y))
            if not self.compact:
                for x in range(5):
                    self.drop(('b', x, y))


@cache
def keccak_f1600_script(*, compact=True, optimize=True, packed_rows=True):
    """Replace a 200-byte packed Keccak state with the permuted state.

    Lanes are packed little-endian in x+5y order. They are reversed before
    rotation because the Script byte-vector shifts treat lanes as big-endian.
    The program preserves items below the state and entries on the altstack.
    """
    if compact and optimize and packed_rows:
        return _packed_keccak()

    code = bytearray(asm('OP_SIZE') + number(_STATE_BYTES) + asm('OP_NUMEQUALVERIFY'))
    reverse = _reverse_bytes(_LANE_BYTES) if compact and optimize else _REVERSE_LANE
    rotate = _rotate_doubled_lane if compact and optimize else _rotate_left
    split_lane = number(_LANE_BYTES) + asm('OP_SPLIT OP_SWAP') + reverse + asm('OP_SWAP')
    code += split_lane * 24 + reverse
    for constant in _ROUND_CONSTANTS:
        round_code = _Round(compact=compact, rotate=rotate)
        round_code.columns()
        round_code.move_and_rotate()
        round_code.mix_rows(constant)
        assert round_code.lanes == [('a', x, y) for x, y in _POSITIONS]
        code += round_code.code
    concat_lane = asm('OP_SWAP') + reverse + asm('OP_SWAP OP_CAT')
    code += reverse + concat_lane * 24
    return bytes(code)


def _packed_theta():
    # The low-bit mask sits below five rows. XORing rows gives all five
    # column parities at once. The byte rotations shift the lane indices.
    code = asm('OP_DUP')
    for depth in range(2, 6):
        code += number(depth) + asm('OP_PICK OP_XOR')
    code += asm('OP_DUP') + _rotate_bytes(_LANE_BYTES)
    # Mask away the bits crossing lane boundaries, then add the wrap bits.
    code += asm('OP_DUP OP_1 OP_LSHIFT OP_8 OP_PICK OP_INVERT OP_AND OP_SWAP')
    code += number(63) + asm('OP_RSHIFT OP_8 OP_PICK OP_AND OP_OR OP_SWAP')
    code += _rotate_bytes(_ROW_BYTES - _LANE_BYTES) + asm('OP_XOR')
    # Apply the same correction to all rows and split them for rho and pi.
    code += asm('OP_SWAP OP_OVER OP_XOR OP_TOALTSTACK') * 4 + asm('OP_XOR')
    return code + _UNPACK_ROWS


@cache
def _keccak_rows(*, stream_rows=False, short_rotations=False):
    code = bytearray()
    theta = _packed_theta()
    # Chi uses the whole row and its rotations by one and two lanes.
    chi = _PACK_ROW + asm('OP_DUP') + _rotate_bytes(_LANE_BYTES) + asm('OP_INVERT OP_OVER')
    chi += _rotate_bytes(2 * _LANE_BYTES) + asm('OP_AND OP_XOR')
    rho_pi = _Round(compact=True, rotate=_rotate_short_lane if short_rotations else _rotate_packed_lane)
    if stream_rows:
        # After rho and pi produce each row, apply chi immediately and
        # move the row off the main stack before selecting more lanes.
        for y in reversed(range(5)):
            for x in range(5):
                source_x, source_y = _PI_SOURCES[x, y]
                rho_pi.roll(('a', source_x, source_y))
                rho_pi.code += rho_pi.rotate(_ROTATION[source_x][source_y])
            del rho_pi.lanes[-5:]
            rho_pi.code += chi
            if y:
                rho_pi.code += asm('OP_TOALTSTACK')
        round_body = theta + rho_pi.code
    else:
        rho_pi.move_and_rotate(theta_done=True)
        round_body = theta + rho_pi.code + (chi + asm('OP_TOALTSTACK')) * 4 + chi
    for constant in _ROUND_CONSTANTS:
        code += round_body
        code += asm('OP_8 OP_SPLIT OP_SWAP') + push(constant.to_bytes(_LANE_BYTES, 'big'))
        code += asm('OP_XOR OP_SWAP OP_CAT') + asm('OP_FROMALTSTACK') * 4

    return bytes(code)


def _packed_keccak():
    code = bytearray(asm('OP_SIZE') + number(_STATE_BYTES) + asm('OP_NUMEQUALVERIFY'))
    code += push(_LANE_LSB_MASK) + asm('OP_SWAP')
    reverse = _reverse_bytes(_LANE_BYTES)
    split_lane = asm('OP_8 OP_SPLIT OP_SWAP') + reverse + asm('OP_SWAP')
    code += split_lane * 24 + reverse
    code += (_PACK_ROW + asm('OP_TOALTSTACK')) * 4 + _PACK_ROW + asm('OP_FROMALTSTACK') * 4
    code += _keccak_rows() + asm('OP_TOALTSTACK') * 4 + _UNPACK_ROWS
    concat_lane = asm('OP_SWAP') + reverse + asm('OP_SWAP OP_CAT')
    return bytes(code) + reverse + concat_lane * 24 + asm('OP_NIP')


@cache
def _state_permutation(*, stream_rows=False, short_rotations=False):
    """Permute an internal state whose lanes are already big-endian."""
    return (push(_LANE_LSB_MASK) + asm('OP_SWAP') + (number(_ROW_BYTES) + asm('OP_SPLIT')) * 4
            + _keccak_rows(stream_rows=stream_rows, short_rotations=short_rotations)
            + _PACK_ROW + asm('OP_NIP'))


@cache
def _reverse_lane_stream(lanes):
    reverse = _reverse_bytes(_LANE_BYTES)
    if lanes == 1:
        return reverse
    step = asm('OP_8 OP_SPLIT OP_SWAP') + reverse + asm('OP_ROT OP_SWAP OP_CAT OP_SWAP')
    return asm('OP_0 OP_SWAP') + step * (lanes - 1) + reverse + asm('OP_CAT')


def _byte_swap_masks(rate):
    """Build the three lane-wise swap masks below the sponge state."""
    code = asm('OP_TOALTSTACK')
    lanes = rate // _LANE_BYTES
    grow = asm('OP_DUP OP_CAT') * (lanes - 1).bit_length()
    for group in (1, 2, 4):
        mask = (bytes(group) + b'\xff' * group) * (_LANE_BYTES // (2 * group))
        code += push(mask) + grow + number(rate) + asm('OP_SPLIT OP_DROP')
    return code + asm('OP_FROMALTSTACK')


def _reverse_rate_bytes(*, above):
    """Reverse all eight-byte lanes in the rate block using the shared masks."""
    code = b''
    for index, bits in enumerate((8, 16, 32)):
        shift = number(bits)
        # t = (x XOR (x >> bits)) AND mask. XOR t into the low groups
        # and t << bits into the high groups to exchange them in place.
        code += asm('OP_DUP OP_DUP') + shift + asm('OP_RSHIFT OP_XOR')
        code += number(above + 4 - index) + asm('OP_PICK OP_AND OP_DUP')
        code += shift + asm('OP_LSHIFT OP_XOR OP_XOR')
    return code


def _shake_script(message_bytes, output_bytes, rate, *, compact=True, optimize=True,
                  packed_rows=True, packed_state=True, stream_rows=True, vector_bytes=True):
    if type(message_bytes) is not int or message_bytes < 0:
        raise ValueError('message length must be a nonnegative integer')
    if type(output_bytes) is not int or output_bytes < 1:
        raise ValueError('output length must be a positive integer')

    # SHAKE's 1111 suffix, followed by pad10*1. A one-byte pad is 0x9f.
    blocks, partial = divmod(message_bytes, rate)
    padding = bytearray(rate - partial)
    padding[0] = 0x1f
    padding[-1] |= 0x80

    code = bytearray(asm('OP_SIZE') + number(message_bytes) + asm('OP_NUMEQUALVERIFY'))
    packed_state = packed_state and compact and optimize and packed_rows
    vector_bytes = vector_bytes and packed_state
    if vector_bytes:
        code += _byte_swap_masks(rate)
    code += push(padding) + asm('OP_CAT') + push(bytes(_STATE_BYTES))
    # Keep all state lanes big-endian across permutations. Convert only the
    # bytes that cross the sponge boundary, in FIPS 202 little-endian order.
    if packed_state:
        permutation = _state_permutation(stream_rows=stream_rows, short_rotations=vector_bytes)
        absorb_bytes = _reverse_rate_bytes(above=1) if vector_bytes else _reverse_lane_stream(rate // _LANE_BYTES)
        squeeze_bytes = _reverse_rate_bytes(above=2) if vector_bytes else absorb_bytes
    else:
        permutation = keccak_f1600_script(compact=compact, optimize=optimize, packed_rows=packed_rows)
        absorb_bytes = squeeze_bytes = b''
    absorb = (
        asm('OP_SWAP') + number(rate) + asm('OP_SPLIT OP_TOALTSTACK') + absorb_bytes
        + push(bytes(_STATE_BYTES - rate)) + asm('OP_CAT OP_XOR')
        + permutation + asm('OP_FROMALTSTACK OP_SWAP')
    )
    code += absorb * (blocks + 1) + asm('OP_NIP')

    extra_blocks, final_index = divmod(output_bytes - 1, rate)
    # One accumulator concatenates successive rate blocks. Each permutation
    # still acts only on the state at the top of the stack.
    code += asm('OP_0 OP_SWAP')
    squeeze = (
        asm('OP_DUP') + number(rate) + asm('OP_SPLIT OP_DROP') + squeeze_bytes
        + asm('OP_ROT OP_SWAP OP_CAT OP_SWAP')
        + permutation
    )
    code += squeeze * extra_blocks
    final_size = final_index + 1
    if vector_bytes:
        code += number(rate) + asm('OP_SPLIT OP_DROP') + absorb_bytes
        if final_size != rate:
            code += number(final_size) + asm('OP_SPLIT OP_DROP')
    elif packed_state:
        lanes = (final_size + _LANE_BYTES - 1) // _LANE_BYTES
        lane_bytes = lanes * _LANE_BYTES
        code += number(lane_bytes) + asm('OP_SPLIT OP_DROP') + _reverse_lane_stream(lanes)
        if final_size != lane_bytes:
            code += number(final_size) + asm('OP_SPLIT OP_DROP')
    else:
        code += number(final_size) + asm('OP_SPLIT OP_DROP')
    code += asm('OP_CAT')
    if vector_bytes:
        code += asm('OP_NIP') * 3
    return bytes(code)


def shake128_script(message_bytes, output_bytes):
    """Replace a byte vector of the specified length with a SHAKE128 XOF."""
    return _shake_script(message_bytes, output_bytes, rate=168)


def shake256_script(message_bytes, output_bytes, *, compact=True, optimize=True, packed_rows=True,
                    packed_state=True, stream_rows=True, vector_bytes=True):
    """Replace a byte vector of the specified length with a SHAKE256 XOF."""
    return _shake_script(message_bytes, output_bytes, rate=136, compact=compact, optimize=optimize,
                         packed_rows=packed_rows, packed_state=packed_state, stream_rows=stream_rows,
                         vector_bytes=vector_bytes)

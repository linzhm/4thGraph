"""Fixed-length FIPS 202 SHAKE128 and SHAKE256 bytecode for Bitcoin Script.

The permutation uses byte-vector shifts, XOR, AND and INVERT on eight-byte
lanes. These are Genesis opcodes, with no dependency on Chronicle's numeric
shift extensions. Lengths are fixed when the script is generated.
"""

from functools import cache
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from shared.script import asm, number, push


_LANE_BYTES = 8
_STATE_BYTES = 200
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
_REVERSE_LANE = (
    asm('OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK') * (_LANE_BYTES - 1)
    + asm('OP_FROMALTSTACK OP_CAT') * (_LANE_BYTES - 1)
)


def _rotate_left(bits):
    if bits == 0:
        return b''
    return (
        asm('OP_DUP') + number(bits) + asm('OP_LSHIFT OP_SWAP')
        + number(64 - bits) + asm('OP_RSHIFT OP_OR')
    )


class _Round:
    """Resolve named lanes to stack offsets while emitting one round."""

    def __init__(self):
        self.code = bytearray()
        self.lanes = [('a', x, y) for x, y in _POSITIONS]

    def pick(self, lane):
        depth = len(self.lanes) - 1 - self.lanes.index(lane)
        self.code += number(depth) + asm('OP_PICK')
        self.lanes.append(None)

    def roll(self, lane):
        position = self.lanes.index(lane)
        depth = len(self.lanes) - 1 - position
        if depth:
            self.code += number(depth) + asm('OP_ROLL')
        self.lanes.append(self.lanes.pop(position))

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
            self.pick(('c', (x - 1) % 5))
            self.pick(('c', (x + 1) % 5))
            self.code += _rotate_left(1)
            self.binary('OP_XOR')
            self.name(('d', x))
        for x in range(5):
            self.drop(('c', x))

    def move_and_rotate(self):
        for x, y in _POSITIONS:
            source_x, source_y = _PI_SOURCES[x, y]
            self.roll(('a', source_x, source_y))
            self.pick(('d', source_x))
            self.binary('OP_XOR')
            self.code += _rotate_left(_ROTATION[source_x][source_y])
            self.name(('b', x, y))
        for x in range(5):
            self.drop(('d', x))

    def mix_rows(self, round_constant):
        for y in range(5):
            for x in range(5):
                self.pick(('b', (x + 1) % 5, y))
                self.code += asm('OP_INVERT')
                self.pick(('b', (x + 2) % 5, y))
                self.binary('OP_AND')
                self.pick(('b', x, y))
                self.binary('OP_XOR')
                if x == y == 0:
                    self.code += push(round_constant.to_bytes(_LANE_BYTES, 'big')) + asm('OP_XOR')
                self.name(('a', x, y))
            for x in range(5):
                self.drop(('b', x, y))


@cache
def keccak_f1600_script():
    """Replace a 200-byte packed Keccak state with the permuted state.

    Lanes are packed little-endian in x+5y order. They are reversed before
    rotation because the Script byte-vector shifts treat lanes as big-endian.
    The program preserves items below the state and entries on the altstack.
    """
    code = bytearray(asm('OP_SIZE') + number(_STATE_BYTES) + asm('OP_NUMEQUALVERIFY'))
    split_lane = number(_LANE_BYTES) + asm('OP_SPLIT OP_SWAP') + _REVERSE_LANE + asm('OP_SWAP')
    code += split_lane * 24 + _REVERSE_LANE
    for constant in _ROUND_CONSTANTS:
        round_code = _Round()
        round_code.columns()
        round_code.move_and_rotate()
        round_code.mix_rows(constant)
        assert round_code.lanes == [('a', x, y) for x, y in _POSITIONS]
        code += round_code.code
    concat_lane = asm('OP_SWAP') + _REVERSE_LANE + asm('OP_SWAP OP_CAT')
    code += _REVERSE_LANE + concat_lane * 24
    return bytes(code)


def _shake_script(message_bytes, output_bytes, rate):
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
    code += push(padding) + asm('OP_CAT') + push(bytes(_STATE_BYTES))
    permutation = keccak_f1600_script()
    absorb = (
        asm('OP_SWAP') + number(rate) + asm('OP_SPLIT OP_TOALTSTACK')
        + push(bytes(_STATE_BYTES - rate)) + asm('OP_CAT OP_XOR')
        + permutation + asm('OP_FROMALTSTACK OP_SWAP')
    )
    code += absorb * (blocks + 1) + asm('OP_NIP')

    extra_blocks, final_index = divmod(output_bytes - 1, rate)
    # One accumulator concatenates successive rate blocks. Each permutation
    # still acts only on the state at the top of the stack.
    code += asm('OP_0 OP_SWAP')
    squeeze = (
        asm('OP_DUP') + number(rate) + asm('OP_SPLIT OP_DROP OP_ROT OP_SWAP OP_CAT OP_SWAP')
        + permutation
    )
    code += squeeze * extra_blocks
    code += number(final_index + 1) + asm('OP_SPLIT OP_DROP OP_CAT')
    return bytes(code)


def shake128_script(message_bytes, output_bytes):
    """Replace a byte vector of the specified length with a SHAKE128 XOF."""
    return _shake_script(message_bytes, output_bytes, rate=168)


def shake256_script(message_bytes, output_bytes):
    """Replace a byte vector of the specified length with a SHAKE256 XOF."""
    return _shake_script(message_bytes, output_bytes, rate=136)

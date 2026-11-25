"""Lower straight-line P-256 field expressions to stack code."""

from collections import Counter
from dataclasses import dataclass
from functools import cache

from tx_engine import Script

FIELD = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
B3 = 0x1052a18afeafbbb61bc3380063c994352f57141164fb12e2b36ab4ba777720e2
OUTPUTS = ('X', 'Y', 'Z')


@dataclass(frozen=True)
class Expression:
    op: str
    args: tuple


def add(left, right):
    return Expression('ADD', (left, right))


def sub(left, right):
    return Expression('SUB', (left, right))


def mul(left, right):
    return Expression('MUL', (left, right))


def point_product(left, right, left_product, right_product):
    x1, x2 = left
    y1, y2 = right
    return sub(sub(mul(add(x1, y1), add(x2, y2)), left_product), right_product)


# The existing complete projective sum and a=-3 doubling formulas.
ADD_INPUTS = ('x1', 'y1', 'z1', 'x2', 'y2', 'z2')
ADD = (
    ('xx', mul('x1', 'x2')),
    ('yy', mul('y1', 'y2')),
    ('zz', mul('z1', 'z2')),
    ('xy', point_product(('x1', 'x2'), ('y1', 'y2'), 'xx', 'yy')),
    ('xz', point_product(('x1', 'x2'), ('z1', 'z2'), 'xx', 'zz')),
    ('yz', point_product(('y1', 'y2'), ('z1', 'z2'), 'yy', 'zz')),
    ('h', add(mul(-3, 'xz'), mul('b3', 'zz'))),
    ('minus', sub('yy', 'h')),
    ('plus', add('yy', 'h')),
    ('azz', mul(-3, 'zz')),
    ('t', add(mul(3, 'xx'), 'azz')),
    ('k', sub(mul('b3', 'xz'), mul(3, sub('xx', 'azz')))),
    ('X', sub(mul('xy', 'minus'), mul('yz', 'k'))),
    ('Y', add(mul('minus', 'plus'), mul('t', 'k'))),
    ('Z', add(mul('yz', 'plus'), mul('xy', 't'))),
)
DOUBLE_INPUTS = ('x', 'y', 'z')
DOUBLE = (
    ('w', mul(3, mul(sub('x', 'z'), add('x', 'z')))),
    ('s', mul(2, mul('y', 'z'))),
    ('r', mul('y', 's')),
    ('b', mul(2, mul('x', 'r'))),
    ('h', sub(mul('w', 'w'), mul(2, 'b'))),
    ('X', mul('h', 's')),
    ('Y', sub(mul(sub('b', 'h'), 'w'), mul(2, mul('r', 'r')))),
    ('Z', mul(mul('s', 's'), 's')),
)

SIGNED_MOD = 'OP_DEPTH OP_1SUB OP_PICK OP_MOD'
POSITIVE_MOD = 'OP_DEPTH OP_1SUB OP_PICK OP_TUCK OP_MOD OP_OVER OP_ADD OP_SWAP OP_MOD'


@cache
def _emit(text):
    return Script.parse_string(text).raw_serialize()


def _references(value):
    if isinstance(value, str):
        return [] if value == 'b3' else [value]
    if isinstance(value, Expression):
        return [ref for operand in value.args for ref in _references(operand)]
    return []


def _magnitude(value, bounds):
    if isinstance(value, str):
        return bounds[value]
    if isinstance(value, int):
        return abs(value)
    left, right = (_magnitude(operand, bounds) for operand in value.args)
    return left * right if value.op == 'MUL' else left + right


def intermediate_bits(inputs, assignments):
    """Conservative bounds, assuming all input coordinates have |value| < p."""
    bounds = dict.fromkeys(inputs, FIELD - 1)
    bounds['b3'] = B3
    max_bits = 0
    for name, expression in assignments:
        magnitude = _magnitude(expression, bounds)
        max_bits = max(max_bits, magnitude.bit_length())
        bounds[name] = FIELD - 1 if name in OUTPUTS else magnitude
    return max_bits


class _Stack:
    def __init__(self, slots, uses, code=b''):
        self.slots = list(slots)
        self.uses = uses.copy()
        self.code = code

    def access(self, name):
        index = self.slots.index(name)
        depth = len(self.slots) - index - 1
        self.uses[name] -= 1
        if self.uses[name]:
            instruction = ('OP_DUP', 'OP_OVER')[depth] if depth < 2 else f'{depth} OP_PICK'
        else:
            instruction = ('', 'OP_SWAP', 'OP_ROT')[depth] if depth < 3 else f'{depth} OP_ROLL'
            self.slots.pop(index)
        self.code += _emit(instruction) if instruction else b''
        self.slots.append(None)

    def emit_value(self, value):
        if isinstance(value, int):
            self.code += _emit(str(value))
            self.slots.append(None)
        elif value == 'b3':
            self.code += _emit('OP_DEPTH OP_2 OP_SUB OP_PICK')
            self.slots.append(None)
        elif isinstance(value, str):
            self.access(value)
        elif value.op == 'MUL' and value.args[0] == 2:
            self.emit_value(value.args[1])
            self.code += _emit('OP_DUP OP_ADD')
        else:
            left, right = value.args
            if value.op in ('ADD', 'MUL') and left != right:
                reverse = _Stack(self.slots, self.uses, self.code)
                reverse.emit_value(right)
                reverse.emit_value(left)
            else:
                reverse = None
            self.emit_value(left)
            self.emit_value(right)
            if reverse is not None and len(reverse.code) < len(self.code):
                self.slots, self.uses, self.code = reverse.slots, reverse.uses, reverse.code
            self.slots.pop()
            self.code += _emit(f'OP_{value.op}')


def _kernel(inputs, assignments, *, signed_residues):
    uses = Counter(OUTPUTS)
    for _, expression in assignments:
        uses.update(_references(expression))
    stack = _Stack(inputs, uses)
    for name, expression in assignments:
        stack.emit_value(expression)
        stack.slots[-1] = name
        if name in OUTPUTS:
            stack.code += _emit(SIGNED_MOD if signed_residues else POSITIVE_MOD)
    if set(stack.slots) != set(OUTPUTS) or len(stack.slots) != len(OUTPUTS):
        raise ValueError('curve kernel has unconsumed temporaries')
    if tuple(stack.slots) != OUTPUTS:
        for name in OUTPUTS:
            stack.access(name)
    return stack.code


# Dependency order selected by the arithmetic and full-input benchmark.
_ADD_ORDER = ('yy', 'zz', 'azz', 'xx', 't', 'yz', 'xy', 'xz', 'h', 'plus', 'minus', 'k', 'X', 'Y', 'Z')
_DOUBLE_ORDER = ('s', 'Z', 'r', 'b', 'w', 'h', 'Y', 'X')


def _ordered(assignments, order):
    expressions = dict(assignments)
    return tuple((name, expressions[name]) for name in order)


@cache
def curve_blocks(*, signed_residues=True, scheduled=False):
    addition = _ordered(ADD, _ADD_ORDER) if scheduled else ADD
    doubling = _ordered(DOUBLE, _DOUBLE_ORDER) if scheduled else DOUBLE
    code = {
        'ADD_POINTS': _kernel(ADD_INPUTS, addition, signed_residues=signed_residues),
        'DOUBLE_POINT': (_emit('OP_DUP OP_0NOTEQUAL OP_IF')
                         + _kernel(DOUBLE_INPUTS, doubling, signed_residues=signed_residues)
                         + _emit('OP_ENDIF')),
    }
    if signed_residues:
        # The endpoint checks compare integers. Canonicalize X and Z once.
        # Input and output are [..., X, Y, Z]. Y need only stay in the field.
        code['NORMALIZE_ENDPOINT'] = _emit(
            f'{POSITIVE_MOD} OP_SWAP OP_TOALTSTACK OP_SWAP {POSITIVE_MOD} OP_SWAP '
            'OP_FROMALTSTACK OP_SWAP'
        )
    return code

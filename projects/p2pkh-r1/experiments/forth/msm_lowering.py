"""Preserve P-256 mul2 tables and bounded windows until Script lowering."""

from dataclasses import dataclass
from functools import cache
from math import lcm
from random import Random
import re

from ecdsa import NIST256p, ellipticcurve

from curve_compiler import B3, FIELD
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import OPS, asm, decode_num, encode_num, number, push

GENERATOR = NIST256p.generator
ORDER = NIST256p.order
INFINITY = asm("0 1 0")
CAT = asm("OP_CAT")


@dataclass(frozen=True)
class Strategy:
    width: int
    joint: bool = False
    q_width: int | None = None
    affine_g: bool = False

    @property
    def name(self):
        mode = "joint" if self.joint else "split"
        widths = str(self.width) if self.q_width is None else f"{self.width}x{self.q_width}"
        return f"{mode}-{widths}" + ("-affine-g" if self.affine_g else "")

    @classmethod
    def parse(cls, text):
        match = re.fullmatch(r"(split|joint)-([1-9][0-9]?)(?:x([1-9][0-9]?))?(-affine-g)?", text)
        if not match:
            raise ValueError("expected split-N, split-NxM or joint-N, optionally followed by -affine-g")
        layout, width, q_width, affine_g = match.groups()
        return cls(int(width), layout == "joint", int(q_width) if q_width else None, bool(affine_g))


@dataclass(frozen=True)
class WindowPlan:
    strategy: Strategy
    bits: int

    def __post_init__(self):
        strategy = self.strategy
        if strategy.joint and strategy.q_width is not None:
            raise ValueError("joint lookup needs the same digit width for G and Q")
        if strategy.joint and strategy.affine_g:
            raise ValueError("affine-g needs a separate G table with Z=1 at every nonzero index; joint entries also contain multiples of Q")
        widths = (strategy.width, strategy.q_width or strategy.width)
        if any(not 1 <= width <= min(self.bits, 7) for width in widths) or self.table_points > 128:
            raise ValueError("each width must fit the proven scalar bit width and the table must fit 128 points")

    @property
    def table_points(self):
        mode = self.strategy
        return (1 << (2 * mode.width) if mode.joint
                else (1 << mode.width) + (1 << (mode.q_width or mode.width)))

    def counts(self):
        mode = self.strategy
        g_width, q_width = mode.width, mode.q_width or mode.width
        g_last = (self.bits - 1) // g_width * g_width
        q_last = (self.bits - 1) // q_width * q_width
        g_digits, q_digits = g_last // g_width + 1, q_last // q_width + 1
        q_setup_adds = (1 << (q_width - 1)) - 1
        return {
            "g_lookups": 0 if mode.joint else g_digits,
            "q_lookups": 0 if mode.joint else q_digits,
            "joint_lookups": g_digits if mode.joint else 0,
            "g_adds": 0 if mode.joint else g_digits - (g_last > q_last),
            "loop_adds": g_digits - 1 if mode.joint else g_digits + q_digits - 1,
            "loop_doubles": max(g_last, q_last),
            "digit_rounds": g_digits + q_digits - ((self.bits - 1) // lcm(g_width, q_width) + 1),
            "setup_adds": q_setup_adds + ((1 << g_width) - 1) ** 2 if mode.joint else q_setup_adds,
            "setup_doubles": q_setup_adds,
        }


@dataclass(frozen=True)
class Program:
    strategy: Strategy
    pieces: tuple[tuple[bytes, int], ...]
    table_points: int
    kernels: tuple[bytes, ...]
    sections: dict[str, int]

    def emit(self):
        return b"".join(code * count for code, count in self.pieces)


def pick(depth):
    if depth == 0:
        return asm("OP_DUP")
    if depth == 1:
        return asm("OP_OVER")
    return number(depth) + asm("OP_PICK")


def copy_point(points, point, staged=0):
    depth = 3 * (len(points) - points.index(point)) - 1 + staged
    if depth == 2:
        return asm("OP_3DUP")
    return pick(depth) * 3


@cache
def constant_point(index):
    if index == 0:
        return INFINITY
    point = index * GENERATOR
    return number(point.x()) + number(point.y()) + asm("1")


def table_setup(strategy, add, double):
    base = 1 << strategy.width
    q_base = 1 << (strategy.q_width or strategy.width)
    points = []
    code = bytearray()

    def fixed(index):
        code.extend(constant_point(index))
        points.append((index, 0))

    def copy(point, staged=0):
        code.extend(copy_point(points, point, staged))

    def q_row():
        code.extend(asm("OP_FROMALTSTACK OP_FROMALTSTACK 1"))
        points.append((0, 1))
        for v in range(2, q_base):
            if v % 2 == 0:
                copy((0, v // 2))
                code.extend(double)
            else:
                copy((0, v - 1))
                copy((0, 1), staged=3)
                code.extend(add)
            points.append((0, v))

    if strategy.joint:
        fixed(0)
        q_row()
        for u in range(1, base):
            fixed(u)
            for v in range(1, base):
                copy((u, 0))
                copy((0, v), staged=3)
                code.extend(add)
                points.append((u, v))
    else:
        for u in range(base):
            fixed(u)
        code.extend(INFINITY)
        points.append(("q-zero", 0))
        q_row()
    return bytes(code), len(points)


def split_digits(width, *, joint, stride=None):
    radix = number(1 << width)
    code = asm("OP_OVER") + radix + asm("OP_MOD")
    if joint:
        code += number(1 << (stride or width)) + asm("OP_MUL OP_OVER")
        code += radix + asm("OP_MOD OP_ADD OP_TOALTSTACK")
    else:
        code += asm("OP_TOALTSTACK OP_DUP") + radix + asm("OP_MOD OP_TOALTSTACK")
    return code + radix + asm("OP_DIV OP_SWAP") + radix + asm("OP_DIV OP_SWAP")


def lookup(zero_depth, *, affine=False):
    # Retain a depth one larger for the first two picks, which keep an extra copy.
    head = asm("3 OP_MUL") + number(zero_depth + 1) + asm("OP_SWAP OP_SUB OP_DUP OP_PICK OP_SWAP")
    return head + (asm("OP_1SUB OP_PICK") if affine else asm("OP_DUP OP_PICK OP_SWAP OP_1SUB OP_PICK"))


def selected(zero_depth, add, *, accumulate, affine=None):
    take_digit = asm("OP_FROMALTSTACK")
    if accumulate and affine is not None:
        # G[0] is infinity. Leave the accumulator alone instead of passing Z=0 to the affine kernel.
        return (take_digit + asm("OP_DUP OP_IF") + lookup(zero_depth, affine=True) + affine
                + asm("OP_ELSE OP_DROP OP_ENDIF"))
    return take_digit + lookup(zero_depth) + (add if accumulate else b"")


def window_program(plan, add, double, affine=None):
    strategy, bits = plan.strategy, plan.bits
    if strategy.q_width is not None:
        return mixed_program(plan, add, double, affine)
    setup, points = table_setup(strategy, add, double)
    radix = 1 << strategy.width
    full_windows, extra = divmod(bits, strategy.width)
    to_main = asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP")
    pieces = [(setup + to_main, 1), (split_digits(strategy.width, joint=strategy.joint), full_windows)]
    if extra:
        pieces.append((split_digits(extra, joint=strategy.joint, stride=strategy.width), 1))

    if strategy.joint:
        first = selected(3 * points - 1, add, accumulate=False)
        add_window = selected(3 * points + 2, add, accumulate=True)
    else:
        g_add = selected(6 * radix + 2, add, accumulate=True, affine=affine)
        first = selected(3 * radix - 1, add, accumulate=False) + g_add
        add_window = selected(3 * radix + 2, add, accumulate=True) + g_add
    digit_bytes = sum(len(code) * count for code, count in pieces[1:])
    pieces.append((asm("OP_2DROP") + first, 1))
    remaining = full_windows - (not extra)
    if remaining:
        pieces.append((double * strategy.width + add_window, remaining))
    setup_bytes = len(setup + to_main)
    loop_bytes = sum(len(code) * count for code, count in pieces) - setup_bytes - digit_bytes
    return Program(strategy, tuple(pieces), points, (double, add) if affine is None else (double, add, affine),
                   {"table_setup": setup_bytes, "digit_extraction": digit_bytes, "window_loop": loop_bytes})


def periodic_pieces(blocks):
    """Factor consecutive repeating schedules into one block and a repetition count."""
    index = 0
    while index < len(blocks):
        best = (0, 1, 1)
        for length in range(1, min(12, (len(blocks) - index) // 2) + 1):
            unit = blocks[index:index + length]
            offset = index + length
            while blocks[offset:offset + length] == unit:
                offset += length
            count = (offset - index) // length
            score = (count - 1) * sum(map(len, unit))
            if score > best[0]:
                best = (score, length, count)
        _, length, count = best
        yield b"".join(blocks[index:index + length]), count
        index += length * count


def mixed_program(plan, add, double, affine):
    strategy, bits = plan.strategy, plan.bits
    setup, points = table_setup(strategy, add, double)
    q_points = 1 << strategy.q_width
    offsets = sorted(set(range(0, bits, strategy.width)) | set(range(0, bits, strategy.q_width)))
    digits = []
    for offset in offsets:
        code = b""
        if offset % strategy.width == 0:
            radix = number(1 << min(strategy.width, bits - offset))
            code += asm("OP_OVER") + radix + asm("OP_MOD OP_TOALTSTACK OP_SWAP")
            code += radix + asm("OP_DIV OP_SWAP")
        if offset % strategy.q_width == 0:
            radix = number(1 << min(strategy.q_width, bits - offset))
            code += asm("OP_DUP") + radix + asm("OP_MOD OP_TOALTSTACK") + radix + asm("OP_DIV")
        digits.append(code)

    accumulate = False
    previous = offsets[-1]
    steps = []
    for offset in reversed(offsets):
        code = double * (previous - offset)
        for width, table_end, kernel in ((strategy.q_width, q_points, None), (strategy.width, points, affine)):
            if offset % width == 0:
                depth = 3 * table_end - 1 + 3 * accumulate
                code += selected(depth, add, accumulate=accumulate, affine=kernel)
                accumulate = True
        steps.append(code)
        previous = offset
    prepare = setup + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP")
    pieces = [(prepare, 1), *periodic_pieces(digits), (asm("OP_2DROP"), 1), *periodic_pieces(steps)]
    return Program(strategy, tuple(pieces), points, (double, add) if affine is None else (double, add, affine),
                   {"table_setup": len(prepare), "digit_extraction": sum(map(len, digits)),
                    "window_loop": 1 + sum(map(len, steps))})


def repeated(count):
    bits = bin(count)[3:]
    double = asm("OP_DUP OP_CAT")
    if "1" not in bits:
        return double * len(bits)
    save = asm("OP_DUP OP_TOALTSTACK")
    restore = asm("OP_FROMALTSTACK")
    return save + b"".join(double + (restore + save + CAT if bit == "1" else b"") for bit in bits) + restore + asm("OP_DROP")


def reconstruction(prefix, before, pieces, after, kernels):
    matches = re.compile(b"|".join(re.escape(kernel) for kernel in sorted(kernels, key=len, reverse=True)))

    def append(raw, staged):
        encoded = bytearray()
        position = 0
        for match in matches.finditer(raw):
            if position < match.start():
                encoded.extend(push(raw[position:match.start()]) + CAT)
            depth = len(kernels) + 1 + staged - kernels.index(match.group())
            encoded.extend(pick(depth) + CAT)
            position = match.end()
        if position < len(raw):
            encoded.extend(push(raw[position:]) + CAT)
        return min(push(raw) + CAT, bytes(encoded), key=len)

    code = bytearray(b"".join(push(kernel) for kernel in kernels) + push(prefix) + asm("0"))
    code.extend(append(before, 0))
    for raw, count in pieces:
        literal = push(raw)
        compact = asm("0") + append(raw, 1)
        assembled = min(literal, compact, key=len)
        code.extend(min(append(raw * count, 0), assembled + repeated(count) + CAT, key=len))
    code.extend(append(after, 0))
    if len(kernels) == 2:
        code.extend(asm("OP_2SWAP OP_2DROP"))
    else:
        code.extend(asm("OP_TOALTSTACK OP_TOALTSTACK") + asm("OP_2DROP") * (len(kernels) // 2)
                    + asm("OP_DROP") * (len(kernels) % 2) + asm("OP_FROMALTSTACK OP_FROMALTSTACK"))
    return bytes(code)


def opcode_count(script, name):
    count = position = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        if opcode <= 75:
            position += opcode
        elif opcode <= 78:
            width = (1, 2, 4)[opcode - 76]
            position += width + int.from_bytes(script[position:position + width], "little")
        count += opcode == OPS[name]
    return count


def verify_window(program, vector_budget):
    rng = Random(42536)
    vectors = [
        (0, 0, 1), (1, 0, 1), (0, 1, ORDER - 1), (ORDER - 1, 1, 1), (ORDER - 1, ORDER - 1, ORDER - 1),
        (ORDER - 1, ORDER - 1, 1), (1 << 255, 1 << 255, 2), ((1 << 255) - 1, 1 << 128, 3),
        (15, 0, 1), (16, 15, 2), (31, 16, ORDER - 1), (0, 16, 2),
    ]
    vectors += [(rng.randrange(ORDER), rng.randrange(ORDER), rng.randrange(1, ORDER))
                for _ in range(vector_budget - len(vectors))]
    prefix = tuple(map(encode_num, (FIELD, B3, 19)))
    rows = []
    for u, v, k in vectors:
        q = k * GENERATOR
        rows.append(((u, v, q.y(), q.x()), (u + v * k) % ORDER * GENERATOR))
    # Supply the same alternate-stack input as the verification prologue.
    raw = asm("OP_TOALTSTACK") * 4 + program.emit()
    for alt, expected in rows:
        stack, remainder = evaluate(raw, [*prefix, *map(encode_num, reversed(alt))])
        x, y, z = map(decode_num, stack[-3:])
        if stack[:3] != list(prefix) or len(stack) != 3 * program.table_points + 6 or remainder:
            raise ValueError(f"{program.strategy.name}: incorrect stack layout")
        if expected == ellipticcurve.INFINITY:
            if z % FIELD != 0 or x % FIELD != 0 or y % FIELD == 0:
                raise ValueError(f"{program.strategy.name}: incorrect point at infinity")
        elif z % FIELD == 0 or ((x - z * expected.x()) % FIELD or (y - z * expected.y()) % FIELD):
            raise ValueError(f"{program.strategy.name}: incorrect P-256 point for {alt[:2]}")
    return len(rows)

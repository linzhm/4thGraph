"""Affine Groth16 layouts with checked slopes and optional committed pairing lines."""

from functools import lru_cache
from hashlib import sha256
from itertools import chain

from .verifier import (
    FIELD_BYTES, HOST, PSI_X, PSI_Y, Q, SEED_BITS, Curve,
    VerifierStages, affine_lines, dynamic_slots, evaluated_line, fold_msm, prepare_key, proof_packet,
    proof_stack, public_packet, read_proof, require_affine, unpack_packet, unpack_public,
)
from fourthgraph.bsv.script import asm, number, push

LAYOUTS = ("projective", "affine-inline", "affine-witness")
IDENTITY = (0, 0)
PAIRING_STEPS = len(SEED_BITS) + SEED_BITS.count("1")


def encode_fields(values):
    return b"".join(value.to_bytes(FIELD_BYTES, "little") for value in values)


def msm_windows(key, sources):
    """Fixed-base tables shared by the compiler and witness generator."""
    curve = Curve(HOST)
    for index, source in dynamic_slots(sources):
        base = key.ic[index + 1]
        if base is None:
            continue
        for bit in range(0, source.bits, 2):
            if source.bits - bit == 1:
                yield index, bit, (base,)
            else:
                twice = curve.add_host(base, base)
                yield index, bit, (base, twice, curve.add_host(base, twice))
                base = curve.add_host(twice, twice)


@lru_cache(maxsize=8)
def vk_lines(key):
    _, delta, gamma = prepare_key(key)
    return tuple(zip(chain.from_iterable(delta), chain.from_iterable(gamma), strict=True))


def line_packet(key):
    return encode_fields(coord for lines in vk_lines(key) for line in lines for pair in line for coord in pair)


def slope_packet_bytes(window_count):
    return (window_count + PAIRING_STEPS * 2) * FIELD_BYTES


def affine_witness(key, sources, signals, raw_proof, *, lines_in_witness):
    public = public_packet(sources, signals)
    if not public:
        raise ValueError("an affine witness layout requires at least one spend-time public input")
    proof = read_proof(raw_proof)
    packet = proof_packet(key, signals, proof)
    curve = Curve(HOST)
    acc = fold_msm(key, sources)
    slopes = []
    for index, bit, points in msm_windows(key, sources):
        digit = (signals[index] >> bit) & len(points)
        if digit == 0:
            slopes.append(0)
            continue
        point = points[digit - 1]
        if acc is None or acc == curve.negate(point):
            acc = curve.add_host(acc, point)
            slopes.append(0)
        else:
            acc, (_, slope) = curve.affine_line(acc, point, doubling=acc == point)
            slopes.append(slope)
    b_slopes = [coord for step in affine_lines(proof.b) for _, slope in step for coord in slope]
    trace = encode_fields(chain(slopes, b_slopes))
    precomputed = push(line_packet(key)) if lines_in_witness else b""
    return precomputed + push(trace) + push(packet) + push(public)


class PackedFields:
    def __init__(self, field, packet):
        self.field = field
        self.packet = packet

    def read(self, index, *, committed=False):
        width = number(FIELD_BYTES)
        if self.field.chronicle:
            code = number(index * FIELD_BYTES) + width + asm("OP_SUBSTR") if index else width + asm("OP_LEFT")
        else:
            prefix = number(index * FIELD_BYTES) + asm("OP_SPLIT OP_NIP") if index else b""
            code = prefix + width + asm("OP_SPLIT OP_DROP")
        if not committed:
            code += push(b"\x00") + asm("OP_CAT")
        value = self.field.graph.define(code + asm("OP_BIN2NUM"), (self.packet,))
        if not committed:
            self.field.all((self.field.op("OP_LESSTHAN", value, Q),))
        return value


def add_msm_window(f, acc, point, digit, slope):
    """Check the selected affine addition, including the two identity cases."""
    x, y = acc
    px, py = point
    dx, dy = f.sub(px, x), f.sub(py, y)
    distinct_x = f.nonzero(dx)
    same_y = f.equal(dy, 0)
    # All finite accumulator states are in the odd-order subgroup, so y != 0.
    finite = f.nonzero(y)
    active = f.nonzero(digit)
    regular = f.op("OP_BOOLOR", distinct_x, same_y)
    has_slope = f.op("OP_BOOLAND", active, f.op("OP_BOOLAND", finite, regular))
    denominator = f.select(distinct_x, dx, f.mul(2, y))
    numerator = f.select(distinct_x, dy, f.mul(3, f.mul(x, x)))
    mismatch = f.sub(f.mul(slope, denominator), numerator)
    f.all((f.equal(f.select(has_slope, mismatch, slope), 0),))

    nx = f.reduce(f.sub(f.sub(f.mul(slope, slope), x), px))
    ny = f.reduce(f.sub(f.mul(slope, f.sub(x, nx)), y))
    return tuple(
        f.select(active, f.select(finite, f.select(regular, result, 0), base), old)
        for result, base, old in zip((nx, ny), point, acc, strict=True)
    )


def checked_b_line(curve, point, other, slope, *, doubling):
    x, y = point
    ax, ay = other
    if doubling:
        denominator = curve.scale(y, 2)
        numerator = curve.scale(curve.square(x), 3)
    else:
        denominator = curve.sub(ax, x)
        numerator = curve.sub(ay, y)
    f = curve.tower.fp
    mismatch = curve.sub(curve.mul(slope, denominator), numerator)
    f.all((f.op("OP_BOOLOR", *(f.nonzero(limb) for limb in denominator)),
           *(f.equal(limb, 0) for limb in mismatch)))
    nx = curve.reduce(curve.sub(curve.sub(curve.square(slope), x), ax))
    ny = curve.sub(curve.mul(slope, curve.sub(x, nx)), y)
    return (nx, ny), (curve.sub(curve.mul(slope, x), y), slope)


class AffineStages(VerifierStages):
    def __init__(self, key, sources, *, lines_in_witness, chronicle=False, optimize=False):
        self.witness_items = 2 if lines_in_witness else 1
        super().__init__(key, sources, chronicle=chronicle, optimize=optimize, extra_inputs=self.witness_items)
        if not self.slots:
            raise ValueError("an affine witness layout requires at least one spend-time public input")
        self.lines_in_witness = lines_in_witness
        self.windows = tuple(msm_windows(key, sources))
        inputs = self.field.graph.inputs
        self.trace = PackedFields(self.field, inputs[self.witness_items - 1])
        self.lines = PackedFields(self.field, inputs[0]) if lines_in_witness else None

    def read_witness(self):
        self.setup = b""
        if self.lines_in_witness:
            self.setup += asm("OP_3 OP_PICK OP_SHA256") + push(sha256(line_packet(self.key)).digest())
            self.setup += asm("OP_EQUALVERIFY")
        trace_bytes = slope_packet_bytes(len(self.windows))
        self.setup += asm("OP_2 OP_PICK OP_SIZE") + number(trace_bytes) + asm("OP_NUMEQUALVERIFY OP_DROP")
        self.setup += (asm("OP_TOALTSTACK") + unpack_packet(self.proof_elements)
                       + asm("OP_FROMALTSTACK") + unpack_public(self.slots))
        inputs = self.field.graph.inputs
        end = self.witness_items + self.proof_elements
        return proof_stack(inputs[self.witness_items:end]), inputs[end:]

    def check_public_inputs(self, public):
        f = self.field
        scalars = {index: value for (index, _), value in zip(self.slots, public, strict=True)}
        widths = {index: source.bits for index, source in self.slots}
        acc = fold_msm(self.key, self.sources) or IDENTITY
        for offset, (index, bit, points) in enumerate(self.windows):
            quotient = f.op("OP_DIV", scalars[index], 4) if bit + 2 < widths[index] else 0
            digit = f.sub(scalars[index], f.mul(quotient, 4))
            scalars[index] = quotient
            point = points[0]
            if len(points) == 3:
                upper = f.half_digit(digit)
                odd = f.sub(digit, f.mul(upper, 2))
                point = tuple(f.select(upper, f.select(odd, p3, p2), p1)
                              for p1, p2, p3 in zip(*points, strict=True))
            acc = add_msm_window(f, acc, point, digit, self.trace.read(offset))
        return Curve(self.tower).negate(acc), f.nonzero(acc[1])

    def miller_loop(self, pairing_key, proof):
        a, b, c, z = proof
        vk_point, vk_finite = pairing_key
        tower, f = self.tower, self.field
        curve = Curve(tower, twist=True)
        f.all(tuple(f.equal(limb, 0) for limb in curve.equation(b)))
        minus_c = Curve(tower).negate(c)
        prepared = iter(vk_lines(self.key))
        step = 0
        acc, current = z, b
        for bit in SEED_BITS:
            acc = tower.square12(acc)
            for doubling in ((True, False) if bit == "1" else (True,)):
                offset = len(self.windows) + step * 2
                slope = self.trace.read(offset), self.trace.read(offset + 1)
                current, line = checked_b_line(curve, current, current if doubling else b, slope, doubling=doubling)
                delta, gamma = next(prepared)
                zero_intercept = gamma[0] == curve.zero
                if self.lines_in_witness:
                    pairs = tuple(tuple(self.lines.read(step * 8 + pair * 2 + limb, committed=True)
                                        for limb in range(2)) for pair in range(4))
                    delta, gamma = pairs[:2], pairs[2:]
                gamma_line = evaluated_line(tower, vk_point, gamma)
                if zero_intercept:
                    gamma_line = tuple(
                        tuple(f.select(vk_finite, limb, identity) for limb, identity in zip(pair, unit, strict=True))
                        for pair, unit in zip(gamma_line, ((1, 0), (0, 0), (0, 0)), strict=True)
                    )
                acc = tower.mul_line(acc, evaluated_line(tower, a, line))
                acc = tower.mul_line(acc, evaluated_line(tower, minus_c, delta))
                acc = tower.mul_line(acc, gamma_line)
                step += 1
            if bit == "1":
                acc = tower.mul12(acc, z)
        bx, by = (tower.conjugate2(value) for value in b)
        psi = tower.mul2(bx, PSI_X), tower.scale2(tower.mul2(by, PSI_Y), -1)
        require_affine(tower, curve, (*current, curve.one), psi)
        fixed, _, _ = prepare_key(self.key)
        return acc, fixed, z

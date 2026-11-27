"""Affine Groth16 layouts with checked slopes and optional committed pairing lines."""

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from itertools import chain

from .field import FP2_RULES
from .verifier import (
    FIELD_BYTES, HOST, PSI_X, PSI_Y, Q, SEED_BITS, Curve,
    VerifierStages, affine_lines, dynamic_slots, evaluated_line, fold_msm, prepare_key, proof_packet,
    proof_stack, public_packet, read_proof, require_affine, unpack_packet, unpack_public,
)
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.compiler.curve_windows import SignedRadix4Window, double_from_affine_slope, signed_radix4

LAYOUTS = ("projective", "affine-inline", "affine-witness")
MSM_STRATEGIES = ("unsigned-radix4", "signed-radix4")
MSM_TABLES = ("points", "doubling-slopes", "deferred-doubling-slopes")
MILLER_REDUCTIONS = ("per-operation", "per-step", "per-round", "split-chord", "split-chord-residue")
MILLER_KERNELS = ("cross-products", "direct-normalized")
IDENTITY = (0, 0)
PAIRING_STEPS = len(SEED_BITS) + SEED_BITS.count("1")


def encode_fields(values):
    return b"".join(value.to_bytes(FIELD_BYTES, "little") for value in values)


@dataclass(frozen=True)
class MsmWindow:
    index: int
    bit: int
    points: tuple
    signed: SignedRadix4Window | None = None


def msm_windows(key, sources, *, strategy=MSM_STRATEGIES[0]):
    """Fixed-base tables shared by the compiler and witness generator."""
    curve = Curve(HOST)
    for index, source in dynamic_slots(sources):
        base = key.ic[index + 1]
        if base is None:
            continue
        if strategy == "signed-radix4":
            for window, digits in enumerate(signed_radix4(source.limit - 1)):
                if digits.maximum_magnitude == 1:
                    yield MsmWindow(index, window * 2, (base,), digits)
                else:
                    twice = curve.add_host(base, base)
                    yield MsmWindow(index, window * 2, (base, twice), digits)
                    if digits.carry:
                        base = curve.add_host(twice, twice)
            continue
        for bit in range(0, source.bits, 2):
            if source.bits - bit == 1:
                yield MsmWindow(index, bit, (base,))
            else:
                twice = curve.add_host(base, base)
                yield MsmWindow(index, bit, (base, twice, curve.add_host(base, twice)))
                base = curve.add_host(twice, twice)


@lru_cache(maxsize=8)
def vk_lines(key):
    _, delta, gamma = prepare_key(key)
    return tuple(zip(chain.from_iterable(delta), chain.from_iterable(gamma), strict=True))


def line_packet(key):
    return encode_fields(coord for lines in vk_lines(key) for line in lines for pair in line for coord in pair)


def slope_packet_bytes(window_count):
    return (window_count + PAIRING_STEPS * 2) * FIELD_BYTES


def affine_witness(key, sources, signals, raw_proof, *, lines_in_witness, msm=MSM_STRATEGIES[0]):
    public = public_packet(sources, signals)
    if not public:
        raise ValueError("an affine witness layout requires at least one spend-time public input")
    proof = read_proof(raw_proof)
    packet = proof_packet(key, signals, proof)
    curve = Curve(HOST)
    acc = fold_msm(key, sources)
    slopes = []
    remaining = list(signals)
    for window in msm_windows(key, sources, strategy=msm):
        index, bit, points = window.index, window.bit, window.points
        if window.signed is None:
            digit = (signals[index] >> bit) & len(points)
        else:
            digit, remaining[index] = window.signed.split(remaining[index])
        if digit == 0:
            slopes.append(0)
            continue
        point = points[abs(digit) - 1]
        if digit < 0:
            point = curve.negate(point)
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
        decode = (b"" if committed else push(b"\x00") + asm("OP_CAT")) + asm("OP_BIN2NUM")
        value = self.field.graph.packet_slice(self.packet, index * FIELD_BYTES, FIELD_BYTES,
                                              decode=decode, chronicle=self.field.chronicle)
        if not committed:
            self.field.all((self.field.op("OP_LESSTHAN", value, Q),))
        return value


def add_msm_window(f, acc, point, digit, slope, *, bounded=False, defer_reductions=False, shifted=False):
    """Check the selected affine addition, including the two identity cases."""
    x, y = acc
    px, py = point
    dx, dy = f.sub(px, x), f.sub(py, y)
    distinct_x = f.nonzero(dx)
    same_y = f.equal(dy, 0)
    # All finite accumulator states are in the odd-order subgroup, so y != 0.
    # A reduced coordinate and a bounded digit are zero in Fp exactly when
    # their Script integer is zero.
    finite = f.op("OP_0NOTEQUAL", y) if bounded else f.nonzero(y)
    if shifted:
        active = f.op("OP_NUMNOTEQUAL", digit, 1)
    else:
        active = f.op("OP_0NOTEQUAL", digit) if bounded else f.nonzero(digit)
    regular = f.op("OP_BOOLOR", distinct_x, same_y)
    has_slope = f.op("OP_BOOLAND", active, f.op("OP_BOOLAND", finite, regular))
    denominator = f.select(distinct_x, dx, f.mul(2, y))
    numerator = f.select(distinct_x, dy, f.mul(3, f.mul(x, x)))
    mismatch = f.sub(f.mul(slope, denominator), numerator)
    f.all((f.equal(f.select(has_slope, mismatch, slope), 0),))

    nx = f.sub(f.sub(f.mul(slope, slope), x), px)
    if not defer_reductions:
        nx = f.reduce(nx)
    ny = f.sub(f.mul(slope, f.sub(x, nx)), y)
    if not defer_reductions:
        ny = f.reduce(ny)
    # BOOLOR returns a normalized 0 or 1, so it can also mask a coordinate.
    selected = tuple(
        f.select(active, f.select(finite, f.mul(regular, result) if bounded else f.select(regular, result, 0),
                                  base), old)
        for result, base, old in zip((nx, ny), point, acc, strict=True)
    )
    # The selected table point may have unreduced coordinates. Reduce either
    # branch before the next window uses the zero test on the accumulator.
    return tuple(map(f.reduce, selected)) if defer_reductions else selected


def line_slope_residual(curve, point, other, slope, *, doubling):
    x, y = point
    ax, ay = other
    if doubling:
        denominator = curve.scale(y, 2)
        numerator = curve.scale(curve.square(x), 3)
    else:
        denominator = curve.sub(ax, x)
        numerator = curve.sub(ay, y)
    return denominator, curve.sub(curve.mul(slope, denominator), numerator)


def checked_b_line(curve, point, other, slope, *, doubling):
    x, y = point
    ax, _ = other
    f = curve.tower.fp
    denominator, mismatch = line_slope_residual(curve, point, other, slope, doubling=doubling)
    f.all((f.op("OP_BOOLOR", *(f.nonzero(limb) for limb in denominator)),
           *(f.equal(limb, 0) for limb in mismatch)))
    nx = curve.reduce(curve.sub(curve.sub(curve.square(slope), x), ax))
    ny = curve.sub(curve.mul(slope, curve.sub(x, nx)), y)
    return (nx, ny), (curve.sub(curve.mul(slope, x), y), slope)


def checked_normalized_b_line(curve, point, other, slope, *, doubling):
    x, y = point
    ax, _ = other
    f = curve.tower.fp
    with f.residue_block():
        denominator, mismatch = line_slope_residual(curve, point, other, slope, doubling=doubling)
    # The initial proof coordinates and each subsequent point are reduced.
    # Since 2 is invertible, a tangent denominator vanishes exactly when y does.
    nonzero = (tuple(f.op("OP_0NOTEQUAL", limb) for limb in y) if doubling
               else tuple(map(f.nonzero, denominator)))
    f.all((f.op("OP_BOOLOR", *nonzero), *(f.equal(limb, 0) for limb in mismatch)))
    with f.residue_block():
        nx = curve.sub(curve.sub(curve.square(slope), x), ax)
        intercept = curve.sub(curve.mul(slope, x), y)
    nx = curve.reduce(nx)
    # Reuse the line intercept for y' = (slope*x - y) - slope*x'.
    with f.residue_block():
        ny = curve.sub(intercept, curve.mul(slope, nx))
    intercept = curve.reduce(intercept)
    return (nx, curve.reduce(ny)), (intercept, slope)


def double_msm_point(field, point, trusted_point, *, defer_reductions):
    host = Curve(HOST)
    _, (_, slope) = host.affine_line(trusted_point, trusted_point, doubling=True)
    # Give the compiler the slope as a shared Script value. A constant-folded
    # square here would materialize a second full-width field literal.
    slope = field.value(slope)
    if defer_reductions:
        # A full public scalar needs at most 256 table doublings. The x
        # recurrence increases by at most one bit per doubling after the
        # slope square, and y uses only a constant times x plus its old value.
        with field.residue_block():
            return double_from_affine_slope(field, point, slope)
    return double_from_affine_slope(field, point, slope)


class AffineStages(VerifierStages):
    def __init__(self, key, sources, *, lines_in_witness, chronicle=False, optimize=False, fp2_rules=FP2_RULES,
                 fp2_selection="uniform", msm=MSM_STRATEGIES[0], msm_table=MSM_TABLES[0],
                 miller_reductions=MILLER_REDUCTIONS[0], miller_kernel=MILLER_KERNELS[0]):
        self.witness_items = 2 if lines_in_witness else 1
        super().__init__(key, sources, chronicle=chronicle, optimize=optimize, extra_inputs=self.witness_items,
                         fp2_rules=fp2_rules, fp2_selection=fp2_selection)
        if not self.slots:
            raise ValueError("an affine witness layout requires at least one spend-time public input")
        self.lines_in_witness = lines_in_witness
        self.msm = msm
        self.msm_table = msm_table
        self.miller_reductions = miller_reductions
        self.direct_miller = miller_kernel == "direct-normalized"
        self.tower.direct_lines = self.direct_miller
        self.windows = tuple(msm_windows(key, sources, strategy=msm))
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
        if self.msm == "signed-radix4":
            return self.check_signed_msm(public)
        f = self.field
        scalars = {index: value for (index, _), value in zip(self.slots, public, strict=True)}
        widths = {index: source.bits for index, source in self.slots}
        acc = fold_msm(self.key, self.sources) or IDENTITY
        for offset, window in enumerate(self.windows):
            index, bit, points = window.index, window.bit, window.points
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

    def check_signed_msm(self, public):
        f = self.field
        scalars = {index: value for (index, _), value in zip(self.slots, public, strict=True)}
        acc = fold_msm(self.key, self.sources) or IDENTITY
        derive = self.msm_table != "points"
        defer_reductions = self.msm_table == "deferred-doubling-slopes"
        bases = {}

        def divmod_script(value, radix):
            return f.op("OP_DIV", value, radix), f.op("OP_MOD", value, radix)

        for offset, window in enumerate(self.windows):
            index, points, step = window.index, window.points, window.signed
            shifted = defer_reductions and step.carry
            digit, scalars[index] = step.split(scalars[index], add=f.add, sub=f.sub, divide=divmod_script,
                                              shifted=shifted)
            point = points[0]
            if derive:
                point = bases.get(index)
                if point is None:
                    point = tuple(map(f.value, points[0]))
            if len(points) == 2:
                twice = f.op("OP_NUMEQUAL", digit, 3 if shifted else 2)
                doubled = (double_msm_point(f, point, points[0], defer_reductions=defer_reductions)
                           if derive else points[1])
                px, py = (f.select(twice, high, low) for low, high in zip(point, doubled, strict=True))
                if derive and step.carry:
                    # The next radix-4 window's base is four times this base.
                    bases[index] = double_msm_point(f, doubled, points[1], defer_reductions=defer_reductions)
                if shifted:
                    py = f.op("OP_IF OP_NEGATE OP_ENDIF", py, f.op("OP_NOT", digit))
                elif step.carry:
                    negative = f.op("OP_LESSTHAN", digit, 0)
                    py = f.select(negative, f.sub(0, py), py)
                point = px, py
            acc = add_msm_window(f, acc, point, digit, self.trace.read(offset), bounded=True,
                                 defer_reductions=defer_reductions, shifted=shifted)
        return Curve(self.tower).negate(acc), f.op("OP_0NOTEQUAL", acc[1])

    def miller_loop(self, pairing_key, proof, *, bits=SEED_BITS):
        a, b, c, z = proof
        vk_point, vk_finite = pairing_key
        tower, f = self.tower, self.field
        curve = Curve(tower, twist=True)
        f.all(tuple(f.equal(limb, 0) for limb in curve.equation(b)))
        minus_c = Curve(tower).negate(c)
        prepared = iter(vk_lines(self.key))
        step = 0
        acc, current = z, b
        split_chord = self.miller_reductions in ("split-chord", "split-chord-residue")
        per_round = self.miller_reductions == "per-round" or split_chord
        per_step = self.miller_reductions == "per-step"
        check_line = checked_normalized_b_line if self.direct_miller else checked_b_line
        for bit in bits:
            if not per_round:
                acc = tower.square12(acc)
            round_lines = []
            for doubling in ((True, False) if bit == "1" else (True,)):
                offset = len(self.windows) + step * 2
                slope = self.trace.read(offset), self.trace.read(offset + 1)
                current, line = check_line(curve, current, current if doubling else b, slope, doubling=doubling)
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
                if per_round or per_step:
                    lines = evaluated_line(tower, a, line), evaluated_line(tower, minus_c, delta), gamma_line
                    if per_round:
                        round_lines.extend(lines)
                    else:
                        acc = tower.mul_lines(acc, lines)
                else:
                    acc = tower.mul_line(acc, evaluated_line(tower, a, line))
                    acc = tower.mul_line(acc, evaluated_line(tower, minus_c, delta))
                    acc = tower.mul_line(acc, gamma_line)
                step += 1
            if split_chord and bit == "1":
                acc = tower.miller_round(acc, round_lines[:3], None)
                if self.miller_reductions == "split-chord-residue":
                    acc = tower.mul12(tower.mul_lines(acc, round_lines[3:]), z)
                else:
                    acc = tower.mul_lines(acc, round_lines[3:], z)
            elif per_round:
                acc = tower.miller_round(acc, round_lines, z if bit == "1" else None)
            elif bit == "1":
                acc = tower.mul12(acc, z)
        bx, by = (tower.conjugate2(value) for value in b)
        psi = tower.mul2(bx, PSI_X), tower.scale2(tower.mul2(by, PSI_Y), -1)
        require_affine(tower, curve, (*current, curve.one), psi)
        fixed, _, _ = prepare_key(self.key)
        return acc, fixed, z

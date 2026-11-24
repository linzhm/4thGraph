"""Fixed-statement BLS12-381 Groth16 verifier and bit-exact witness encoder."""

from dataclasses import dataclass
from functools import lru_cache

from shared.script import number

from compiler import Program
from projective import Jacobian
from field import (
    BETA, EXTENSION_ORDER, ONE, PSI_X, PSI_Y, Q, R, RESIDUE_INVERSE, U, PrimeField, Tower,
)

BITS = bin(U)[3:]


@dataclass(frozen=True)
class VerificationKey:
    alpha: tuple
    beta: tuple
    gamma: tuple
    delta: tuple
    ic: tuple


@dataclass(frozen=True)
class Proof:
    a: tuple
    b: tuple
    c: tuple


class Curve:
    """Affine formulas with a checked inverse when an on-chain slope is supplied."""

    def __init__(self, field, twist=False):
        self.field = field
        self.tower = Tower(field)
        self.twist = twist
        self.b = (4, 4) if twist else 4
        self.add = self.tower.add if twist else field.add
        self.sub = self.tower.sub if twist else field.sub
        self.mul = self.tower.mul2 if twist else field.mul
        self.scale = self.tower.scale if twist else field.mul
        self.reduce = self.tower.normalize if twist else field.reduce

    def equal(self, a, b):
        if self.twist:
            for value in self.sub(a, b):
                self.field.zero(value)
        else:
            self.field.zero(self.sub(a, b))

    def check_point(self, point):
        x, y = point
        self.equal(self.mul(y, y), self.add(self.mul(self.mul(x, x), x), self.b))

    def negate(self, point):
        return point[0], self.reduce(self.scale(point[1], -1))

    def line(self, left, right, *, doubling=False):
        x, y = left
        next_x, next_y = right
        if doubling:
            numerator = self.scale(self.mul(x, x), 3)
            denominator = self.scale(y, 2)
        else:
            numerator = self.sub(next_y, y)
            denominator = self.sub(next_x, x)

        if isinstance(self.field, Program):
            slope = tuple(self.field.wire_field() for _ in range(2)) if self.twist else self.field.wire_field()
        else:
            inverse = self.tower.inverse2(denominator) if self.twist else self.field.inverse(denominator)
            slope = self.reduce(self.mul(numerator, inverse))
            if self.twist:
                for coordinate in slope:
                    self.field.hint(coordinate)
            else:
                self.field.hint(slope)

        denominator = self.reduce(denominator)
        if self.twist:
            a, b = (self.field.nonzero(coordinate) for coordinate in denominator)
            self.field.require(self.field.add(a, b))
        else:
            self.field.require(self.field.nonzero(denominator))
        self.equal(self.mul(denominator, slope), numerator)
        x3 = self.reduce(self.sub(self.sub(self.mul(slope, slope), x), next_x))
        y3 = self.reduce(self.sub(self.mul(slope, self.sub(x, x3)), y))
        intercept = self.reduce(self.sub(self.mul(slope, x), y)) if self.twist else None
        return (x3, y3), slope, intercept

    def mul_seed(self, point):
        current = point
        for bit in BITS:
            current, _, _ = self.line(current, current, doubling=True)
            if bit == "1":
                current, _, _ = self.line(current, point)
        return current

    def add_host(self, left, right):
        if left is None or right is None:
            return right if left is None else left
        if left[0] == right[0] and left[1] != right[1]:
            return None
        if left == right and not self.reduce(left[1]) == ((0, 0) if self.twist else 0):
            return self.line(left, right, doubling=True)[0]
        if left[0] == right[0]:
            return None
        return self.line(left, right)[0]

    def mul_host(self, point, scalar):
        result = None
        for bit in bin(scalar)[2:]:
            result = self.add_host(result, result)
            if bit == "1":
                result = self.add_host(result, point)
        return result


class Host(PrimeField):
    def __init__(self):
        self.hints = []

    def hint(self, value):
        self.hints.append(value)

    def zero(self, a):
        self.require(not self.nonzero(a))


def evaluated_line(tower, point, slope, intercept):
    x, y = point
    return intercept, tower.scale(slope, tower.fp.sub(0, x)), (y, 0)


@lru_cache(maxsize=64)
def prepared_lines(point):
    curve = Curve(Host(), twist=True)
    current = point
    steps = []
    for bit in BITS:
        current, slope, intercept = curve.line(current, current, doubling=True)
        step = [(slope, intercept)]
        if bit == "1":
            current, slope, intercept = curve.line(current, point)
            step.append((slope, intercept))
        steps.append(tuple(step))
    return tuple(steps)


def miller(tower, a, b, c, delta_lines, initial=ONE, *, join_lines=False, projective=False):
    """Positive-seed Ate loop. The fixed delta lines are generated once."""
    curve = Curve(tower.fp, twist=True)
    jacobian = Jacobian(curve)
    current = jacobian.lift(b) if projective else b
    value = initial
    for bit, fixed in zip(BITS, delta_lines, strict=True):
        value = tower.mul12(value, value)
        for index, (slope_delta, intercept_delta) in enumerate(fixed):
            if projective:
                current, line_b = jacobian.add_mixed(current, b, a) if index else jacobian.double(current, a)
            else:
                current, slope, intercept = curve.line(
                    current, b if index else current, doubling=index == 0,
                )
                line_b = evaluated_line(tower, a, slope, intercept)
            line_delta = evaluated_line(tower, c, slope_delta, intercept_delta)
            if join_lines:
                value = tower.mul12(value, tower.join_lines(line_b, line_delta))
            else:
                value = tower.mul_line(tower.mul_line(value, line_b), line_delta)
        if bit == "1" and initial != ONE:
            value = tower.mul12(value, initial)
    return value, current


def fixed_miller(tower, point, lines):
    if point is None:
        return ONE
    value = ONE
    for step in lines:
        value = tower.mul12(value, value)
        for slope, intercept in step:
            value = tower.mul_line(value, evaluated_line(tower, point, slope, intercept))
    return value


def check_point_host(point, twist=False, *, subgroup=True):
    if point is None:
        raise ValueError("expected a finite affine point")
    x, y = point
    coordinates = (*x, *y) if twist else (x, y)
    if any(type(value) is not int or not 0 <= value < Q for value in coordinates):
        raise ValueError("field coordinate outside canonical range")
    curve = Curve(Host(), twist)
    curve.check_point(point)
    if subgroup and curve.mul_host(point, R) is not None:
        raise ValueError("point outside prime-order subgroup")


@lru_cache(maxsize=32)
def prepare_key(key, public_inputs):
    if len(key.ic) != len(public_inputs) + 1:
        raise ValueError("public input count does not match verification key")
    if any(type(x) is not int or not 0 <= x < R for x in public_inputs):
        raise ValueError("public input outside scalar field")
    check_point_host(key.alpha)
    for point in (key.beta, key.gamma, key.delta):
        check_point_host(point, twist=True)
    for point in key.ic:
        if point is not None:
            check_point_host(point)
    host = Host()
    curve = Curve(host)
    tower = Tower(host)
    vk_x = key.ic[0]
    for scalar, point in zip(public_inputs, key.ic[1:], strict=True):
        vk_x = curve.add_host(vk_x, curve.mul_host(point, scalar))
    fixed_alpha = fixed_miller(tower, curve.negate(key.alpha), prepared_lines(key.beta))
    fixed_inputs = fixed_miller(
        tower, curve.negate(vk_x) if vk_x is not None else None, prepared_lines(key.gamma),
    )
    return prepared_lines(key.delta), tower.mul12(fixed_alpha, fixed_inputs)


def check_g1(curve, point):
    curve.check_point(point)
    squared = curve.mul_seed(curve.mul_seed(point))
    curve.equal(squared[0], curve.field.mul(BETA, point[0]))
    curve.equal(squared[1], curve.field.sub(0, point[1]))


def check_g1_projective(curve, point):
    curve.check_point(point)
    jacobian = Jacobian(curve)
    current = jacobian.lift(point)
    for bit in bin(U * U)[3:]:
        current, _ = jacobian.double(current)
        if bit == "1":
            current, _ = jacobian.add_mixed(current, point)
    endomorphism = curve.field.mul(BETA, point[0]), curve.field.sub(0, point[1])
    jacobian.require_affine(current, endomorphism)


def check_g2(curve, original, seed_multiple, *, projective=False):
    x, y = original
    psi_x = curve.mul((x[0], curve.field.sub(0, x[1])), PSI_X)
    psi_y = curve.mul((y[0], curve.field.sub(0, y[1])), PSI_Y)
    if projective:
        Jacobian(curve).require_affine(seed_multiple, (psi_x, curve.scale(psi_y, -1)))
    else:
        curve.equal(seed_multiple[0], psi_x)
        curve.equal(seed_multiple[1], curve.scale(psi_y, -1))


@lru_cache(maxsize=32)
def locking_script(
    key, public_inputs, *, fused=True, join_lines=True, projective_g1=False, projective_g2=False,
    reuse_constants=False,
):
    """Return script bytes, named offsets and a generated stack-depth estimate."""
    delta_lines, constant = prepare_key(key, public_inputs)
    program = Program()
    tower = Tower(program)
    g1, g2 = Curve(program), Curve(program, twist=True)
    a = tuple(program.wire_field() for _ in range(2))
    b = tuple(tuple(program.wire_field() for _ in range(2)) for _ in range(2))
    c = tuple(program.wire_field() for _ in range(2))
    z = tuple(tuple(program.wire_field() for _ in range(2)) for _ in range(6))
    program.mark("subgroups_and_curve")
    g1_check = check_g1_projective if projective_g1 else check_g1
    g1_check(g1, a)
    g1_check(g1, c)
    g2.check_point(b)
    program.mark("miller")
    product, seed_multiple = miller(
        tower, a, b, g1.negate(c), delta_lines, z if fused else ONE,
        join_lines=join_lines, projective=projective_g2,
    )
    check_g2(g2, b, seed_multiple, projective=projective_g2)
    program.mark("residue")
    if not fused:
        product = tower.mul12(product, tower.power12(z, U))
    product = tower.mul12(tower.mul12(product, constant), tower.frobenius(z))
    for coefficient in product[1::2]:
        for limb in coefficient:
            program.zero(limb)
    nonzero = 0
    for coefficient in product[::2]:
        for limb in coefficient:
            nonzero = program.add(nonzero, program.nonzero(limb))
    program.require(nonzero)
    return program.compile(reuse_constants=reuse_constants)


def proof_fields(proof):
    return (*proof.a, *proof.b[0], *proof.b[1], *proof.c)


def unlocking_fields(key, public_inputs, proof, *, projective_g1=False, projective_g2=False):
    """Generate checked arithmetic hints and the residue witness from an affine proof."""
    check_point_host(proof.a)
    check_point_host(proof.b, twist=True)
    check_point_host(proof.c)
    delta_lines, constant = prepare_key(key, public_inputs)
    host = Host()
    g1 = Curve(host)
    tower = Tower(host)
    # The host has already checked subgroup membership by multiplying by R.
    if not projective_g1:
        check_g1(g1, proof.a)
        check_g1(g1, proof.c)
    g1_hint_count = len(host.hints)
    # Projective lines differ by nonzero Fp2 factors, which the residue check
    # projects away. Use the same affine reference product for every profile.
    product, seed_multiple = miller(tower, proof.a, proof.b, g1.negate(proof.c), delta_lines)
    check_g2(Curve(host, twist=True), proof.b, seed_multiple)
    hints = host.hints[:g1_hint_count] if projective_g2 else host.hints
    product = tower.mul12(product, constant)
    z = tower.power12(product, EXTENSION_ORDER - RESIDUE_INVERSE)
    return (*proof_fields(proof), *(limb for coefficient in z for limb in coefficient), *hints)


def unlocking_script(fields):
    return b"".join(number(limb) for limb in reversed(fields))


def verify_host(key, public_inputs, proof):
    """Conventional final exponentiation for comparison with the script residue check."""
    check_point_host(proof.a)
    check_point_host(proof.b, twist=True)
    check_point_host(proof.c)
    delta_lines, constant = prepare_key(key, public_inputs)
    host = Host()
    tower = Tower(host)
    product, _ = miller(tower, proof.a, proof.b, Curve(host).negate(proof.c), delta_lines)
    return tower.power12(tower.mul12(product, constant), EXTENSION_ORDER // R) == ONE

"""Projective BLS12-381 verifier stages with G1 cofactor preimages."""

from itertools import chain

from .affine_witness import msm_windows, signed_msm_points
from .field import HOST, PSI_X, PSI_Y, Q
from .verifier import (
    FIELD_BYTES, G1_EFFECTIVE_COFACTOR, G1_PREIMAGE_BYTES, INFINITY, PACKET_BYTES, SEED_BITS,
    Curve, VerifierStages, choose_point, evaluated_line, fold_msm, prepare_key, require_affine,
)


def g1_add(curve, point, affine):
    # Renes–Costello–Batina Algorithm 8 for the a=0, b=4 curve.
    x, y, z = point
    ax, ay = affine
    xx, yy = curve.mul(x, ax), curve.mul(y, ay)
    xy = curve.add(curve.mul(x, ay), curve.mul(y, ax))
    yz = curve.add(curve.mul(z, ay), y)
    xz = curve.add(curve.mul(z, ax), x)
    bz = curve.scale(z, 12)
    lower, upper = curve.sub(yy, bz), curve.add(yy, bz)
    nx = curve.sub(curve.mul(xy, lower), curve.mul(curve.scale(yz, 12), xz))
    ny = curve.add(curve.mul(upper, lower), curve.mul(curve.scale(xx, 36), xz))
    nz = curve.add(curve.mul(yz, upper), curve.mul(curve.scale(xx, 3), xy))
    return tuple(map(curve.reduce, (nx, ny, nz)))


def g1_double(curve, point, *, reduce_coordinates):
    # Renes–Costello–Batina Algorithm 9. The output is homogeneous.
    x, y, z = point
    yy, zz = curve.square(y), curve.square(z)
    bz = curve.scale(zz, 12)
    yy8 = curve.scale(yy, 8)
    lower = curve.sub(yy, curve.scale(bz, 3))
    upper = curve.add(yy, bz)
    nx = curve.scale(curve.mul(curve.mul(x, y), lower), 2)
    ny = curve.add(curve.mul(lower, upper), curve.mul(yy8, bz))
    nz = curve.mul(yy8, curve.mul(y, z))
    doubled = nx, ny, nz
    return tuple(map(curve.reduce, doubled)) if reduce_coordinates else doubled


def require_g1_image(tower, target, preimage, *, pair_doubles):
    # Multiplication by h_eff maps every curve point into G1 (RFC 9380 §7).
    field, curve = tower.fp, Curve(tower)
    field.all((field.equal(curve.equation(preimage), 0),))
    current = (*preimage, 1)
    bits = bin(G1_EFFECTIVE_COFACTOR)[3:]
    unreduced = False
    for index, bit in enumerate(bits):
        # A homogeneous double is degree four. A pair starts with reduced
        # coordinates and stops before every addition and the finite test.
        boundary = bit == "1" or index == len(bits) - 1
        normalize = not pair_doubles or unreduced or boundary
        current = g1_double(curve, current, reduce_coordinates=normalize)
        unreduced = not normalize
        if bit == "1":
            current = g1_add(curve, current, preimage)
    require_affine(tower, curve, current, target, homogeneous=True)


def g2_double_line(curve, point):
    # Coordinates are (X/Z, Y/Z). The tangent is scaled by 2YZ in Fp2.
    x, y, z = point
    yy, zz = curve.square(y), curve.square(z)
    e = curve.scale(curve.tower.xi(zz), 12)  # 3 * (4 + 4i) * Z²
    three_e = curve.scale(e, 3)
    factor = curve.scale(curve.mul(y, z), 2)
    nx = curve.mul(curve.scale(curve.mul(x, y), 2), curve.sub(yy, three_e))
    ny = curve.sub(curve.square(curve.add(yy, three_e)), curve.scale(curve.square(e), 12))
    nz = curve.scale(curve.mul(yy, factor), 4)
    return (nx, ny, curve.reduce(nz)), curve.sub(yy, e), curve.scale(curve.square(x), 3), factor


def g2_add_line(curve, point, affine):
    x, y, z = point
    ax, ay = affine
    theta = curve.sub(y, curve.mul(ay, z))
    lam = curve.sub(x, curve.mul(ax, z))
    lam2 = curve.square(lam)
    lam3 = curve.mul(lam, lam2)
    g = curve.mul(x, lam2)
    h = curve.sub(curve.add(lam3, curve.mul(z, curve.square(theta))), curve.scale(g, 2))
    nx = curve.mul(lam, h)
    ny = curve.sub(curve.mul(theta, curve.sub(g, h)), curve.mul(lam3, y))
    nz = curve.mul(z, lam3)
    intercept = curve.sub(curve.mul(theta, ax), curve.mul(lam, ay))
    return (nx, ny, nz), intercept, theta, lam


def evaluated_fixed_line(tower, point, line):
    intercept, slope = line
    imaginary = intercept[1]
    if imaginary == 0:
        return evaluated_line(tower, point, line)
    # The residue predicate is in Fp12*/Fp6*. A fixed line can be scaled by
    # a nonzero Fp scalar. Make the imaginary intercept limb one while the
    # third coefficient stays real, omitting a field product in each Fp2 use.
    inverse = pow(imaginary, -1, Q)
    x, y = point
    return (
        HOST.scale2(intercept, inverse),
        tower.scale2(HOST.scale2(slope, inverse), tower.fp.sub(0, x)),
        (tower.fp.mul(y, inverse), 0),
    )


class CofactorStages(VerifierStages):
    def __init__(self, key, sources, *, msm, msm_table, miller_reductions, **options):
        super().__init__(key, sources, proof_elements=(PACKET_BYTES + G1_PREIMAGE_BYTES) // FIELD_BYTES, **options)
        self.msm = msm
        self.msm_table = msm_table
        self.miller_reductions = miller_reductions
        self.tower.direct_lines = True

    def check_g1_a(self, proof):
        require_g1_image(self.tower, proof[0], proof[4], pair_doubles=self.pair_g1_doubles)
        return proof

    def check_g1_c(self, proof):
        require_g1_image(self.tower, proof[2], proof[5], pair_doubles=self.pair_g1_doubles)
        return proof

    def check_public_inputs(self, public):
        if not self.slots or self.msm != "signed-radix4":
            return super().check_public_inputs(public)
        fixed, delta, gamma_lines = prepare_key(self.key)
        gx, gy, *values = public
        field, curve = self.field, Curve(self.tower)
        initial = fold_msm(self.key, self.sources)
        acc = INFINITY if initial is None else (*initial, 1)
        windows = msm_windows(self.key, self.sources, strategy=self.msm)
        for digit, point, shifted in signed_msm_points(field, self.slots, values, windows, table=self.msm_table):
            active = field.op("OP_NUMNOTEQUAL", digit, 1) if shifted else field.op("OP_0NOTEQUAL", digit)
            acc = choose_point(field, active, g1_add(curve, acc, point), acc)
        x, y, z = acc
        finite = field.nonzero(z)
        dx = field.sub(x, field.mul(gx, z))
        dy = field.sub(y, field.mul(gy, z))
        field.all((field.equal(field.select(finite, dx, gx), 0), field.equal(field.select(finite, dy, gy), 0)))
        return fixed, delta, ((gx, field.sub(0, gy)), gamma_lines, finite)

    def miller_loop(self, pairing_key, proof, *, bits=SEED_BITS):
        a, b, c, z, _, _ = proof
        fixed, delta, gamma = pairing_key
        tower, field = self.tower, self.field
        curve = Curve(tower, twist=True)
        field.all(tuple(field.equal(limb, 0) for limb in curve.equation(b)))
        minus_c = Curve(tower).negate(c)
        current, acc = (*b, curve.one), z
        reductions = self.miller_reductions
        split = reductions in ("split-chord", "split-chord-residue")
        per_round = reductions == "per-round" or split
        for step, (bit, lines) in enumerate(zip(bits, delta, strict=True)):
            if not per_round:
                acc = tower.square12(acc)
            round_lines = []
            for index, delta_line in enumerate(lines):
                current, intercept, slope, factor = (g2_add_line(curve, current, b) if index
                                                      else g2_double_line(curve, current))
                # The scaled tangent and chord coefficients are at most a
                # small multiple of Q², within the Miller round's bound.
                line = (intercept, tower.scale2(slope, field.sub(0, a[0])), tower.scale2(factor, a[1]))
                evaluated = [line, evaluated_fixed_line(tower, minus_c, delta_line)]
                if gamma is not None:
                    point, coefficients, finite = gamma
                    gamma_line = evaluated_fixed_line(tower, point, coefficients[step][index])
                    if coefficients[step][index][0] == curve.zero:
                        gamma_line = (field.select(finite, gamma_line[0][0], 1), gamma_line[0][1]), *gamma_line[1:]
                    evaluated.append(gamma_line)
                if per_round:
                    round_lines.extend(evaluated)
                elif reductions == "per-step":
                    acc = tower.mul_lines(acc, evaluated)
                else:
                    for line in evaluated:
                        acc = tower.mul_line(acc, line)
            if split and bit == "1":
                boundary = len(round_lines) // 2
                acc = tower.miller_round(acc, round_lines[:boundary], None)
                if reductions == "split-chord-residue":
                    acc = tower.mul12(tower.mul_lines(acc, round_lines[boundary:]), z)
                else:
                    acc = tower.mul_lines(acc, round_lines[boundary:], z)
            elif per_round:
                acc = tower.miller_round(acc, round_lines, z if bit == "1" else None)
            elif bit == "1":
                acc = tower.mul12(acc, z)
        bx, by = (tower.conjugate2(limb) for limb in b)
        psi = tower.mul2(bx, PSI_X), tower.scale2(tower.mul2(by, PSI_Y), -1)
        require_affine(tower, curve, current, psi, homogeneous=True)
        return acc, fixed, z

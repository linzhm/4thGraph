"""Curve-specific facts and reproducible fixed-base tables for scalar lowering."""
from dataclasses import dataclass
from functools import cache
from operator import add, sub

from fourthgraph.bsv.script import SECP256K1_FIELD
from fourthgraph.stdlib.weierstrass import CoordinateScale


@dataclass(frozen=True)
class Curve:
    name: str
    field: int
    order: int
    a: int
    b: int
    generator: tuple[int, int]
    endomorphism: tuple[int, int] | None = None  # beta, lambda
    scale_root: int | None = None

    def contains(self, point):
        if point is None:
            return True
        x, y = point
        return 0 <= x < self.field and 0 <= y < self.field and (y*y - x*x*x - self.a*x - self.b) % self.field == 0

    def normalized_a0(self):
        """Return the certified model change for the specialized a=0, 3*b=1 kernels."""
        if self.scale_root is None:
            return None
        scale = CoordinateScale(self.field, self.scale_root)
        a, b = scale.coefficients(self.a, self.b)
        if a or 3 * b % self.field != 1:
            raise ValueError(f"invalid a=0, 3*b=1 model for {self.name}")
        return scale


SECP256K1 = Curve(
    "secp256k1", SECP256K1_FIELD, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, 0, 7,
    (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    (0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee,
     0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72),
    scale_root=0x7e8c32a50d81affef6014528bdbdfe776653b213d485953c3801f2356ad9d755,
)
P256 = Curve(
    "p256", 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551, -3,
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
)
SM2 = Curve(
    "sm2", 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff,
    0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123, -3,
    0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93,
    (0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7,
     0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0),
)
CURVES = {curve.name: curve for curve in (SECP256K1, P256, SM2)}
GLV_REFERENCE = "glv-joint-window-2"
GLV_PACKED = "glv-joint-packed-2"
GLV_STACK = "glv-joint-stack-2"
GLV_SCALED = "glv-joint-scaled-2"
JOINT_STRATEGIES = (GLV_REFERENCE, GLV_PACKED, GLV_STACK, GLV_SCALED)


@dataclass(frozen=True)
class ScalarPlan:
    name: str
    lanes: int
    window_bits: int
    windows: int
    eligible: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class SignedRadix4Window:
    maximum_magnitude: int
    carry: bool

    def split(self, scalar, *, add=add, sub=sub, divide=divmod):
        """Return the digit and the remaining scalar using host or Script operations."""
        if not self.carry:
            return scalar, 0
        high, low = divide(add(scalar, 1), 4)
        return sub(low, 1), high


def signed_radix4(maximum):
    """Plan low-first digits for a scalar proved to lie in [0, maximum].

    For a full window, n = 4*floor((n+1)/4) + d with -1 <= d <= 2.
    Recur on the quotient bound so the final carry gets its own window.
    """
    if type(maximum) is not int or maximum < 0:
        raise ValueError("signed radix-4 requires a nonnegative scalar bound")
    while maximum:
        high = (maximum + 1) // 4
        yield SignedRadix4Window(min(maximum, 2), high != 0)
        maximum = high


def scalar_plans(curve, *, joint=False):
    """Describe lowered operations and each technique's eligibility."""
    binary = ScalarPlan("binary", 2 if joint else 1, 1, 256, not joint,
                        "joint binary lowering is unavailable" if joint else None)
    fixed = tuple(ScalarPlan(f"fixed-window-{width}", 1, width, 256 // width, not joint,
                             "requires a single fixed generator" if joint else None)
                  for width in (2, 4))
    eligible = joint and curve == SECP256K1
    glv = tuple(ScalarPlan(strategy, 4, 2, 64,
                           eligible and (strategy != GLV_SCALED or curve.normalized_a0() is not None),
                           None if eligible else "requires the registered secp256k1 GLV implementation")
                for strategy in JOINT_STRATEGIES)
    return binary, *fixed, *glv


def _add(curve, left, right):
    """Build-time affine addition for public constant tables."""
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    p = curve.field
    if x == u:
        if (y + v) % p == 0:
            return None
        slope = (3 * x*x + curve.a) * pow(2 * y, -1, p) % p
    else:
        slope = (v - y) * pow(u - x, -1, p) % p
    X = (slope*slope - x - u) % p
    return X, (slope * (x - X) - y) % p


def _multiples(curve, point, count):
    values = [None]
    for _ in range(count - 1):
        values.append(_add(curve, values[-1], point))
    return tuple(values)


@cache
def fixed_table(curve, *, window_bits=2, split_bits=None):
    """Return affine table points in low-digit-first order. None denotes infinity."""
    if not curve.contains(curve.generator):
        raise ValueError("curve generator is not on its curve")
    if window_bits not in (1, 2, 4):
        raise ValueError("fixed windows must have width 1, 2, or 4")
    low = _multiples(curve, curve.generator, 1 << window_bits)
    if split_bits is None:
        return low
    if window_bits != 2 or not 0 < split_bits < 256:
        raise ValueError("split generator tables require two-bit windows and a valid split width")
    high = curve.generator
    for _ in range(split_bits):
        high = _add(curve, high, high)
    return tuple(_add(curve, row, column) for row in _multiples(curve, high, 4) for column in low)

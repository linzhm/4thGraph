"""Change the coordinate model of a short Weierstrass curve over a prime field."""
from dataclasses import dataclass


@dataclass(frozen=True)
class CoordinateScale:
    field: int
    root: int

    def __post_init__(self):
        if not 0 < self.root < self.field:
            raise ValueError("the scale must be a nonzero field element")

    def factors(self, *, inverse=False):
        u = pow(self.root, -1, self.field) if inverse else self.root
        return pow(u, 2, self.field), pow(u, 3, self.field)

    def coefficients(self, a, b):
        return a * pow(self.root, 4, self.field) % self.field, b * pow(self.root, 6, self.field) % self.field

    def affine(self, point, *, inverse=False):
        if point is None:
            return None
        u2, u3 = self.factors(inverse=inverse)
        x, y = point
        return x * u2 % self.field, y * u3 % self.field

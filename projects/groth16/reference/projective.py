"""Jacobian formulas for y² = x³ + b over the base field or its quadratic extension."""


class Jacobian:
    def __init__(self, curve):
        self.curve = curve
        self.one = (1, 0) if curve.twist else 1

    def lift(self, affine):
        return (*affine, self.one)

    def double(self, point, evaluation_point=None):
        a, s, m, red = self.curve.add, self.curve.sub, self.curve.mul, self.curve.reduce
        scale = self.curve.scale
        x, y, z = point
        y_squared = m(y, y)
        twice_y = a(y, y)
        tangent_numerator = scale(m(x, x), 3)
        dx = scale(m(x, y_squared), 4)
        new_x = s(m(tangent_numerator, tangent_numerator), a(dx, dx))
        new_y = s(m(tangent_numerator, s(dx, new_x)), scale(m(y_squared, y_squared), 8))
        new_z = m(twice_y, z)

        line = None
        if evaluation_point is not None:
            # The evaluation is scaled by 2*Y*Z³ in Fp2.
            z_squared = m(z, z)
            line = self.line_at(
                s(m(tangent_numerator, x), a(y_squared, y_squared)),
                m(tangent_numerator, z_squared), m(new_z, z_squared), evaluation_point,
            )
        return (red(new_x), red(new_y), red(new_z)), line

    def add_mixed(self, point, affine, evaluation_point=None):
        a, s, m, red = self.curve.add, self.curve.sub, self.curve.mul, self.curve.reduce
        x, y, z = point
        other_x, other_y = affine
        z_squared = m(z, z)
        dx = s(m(other_x, z_squared), x)
        dy = s(m(other_y, m(z, z_squared)), y)
        dx_squared = m(dx, dx)
        dx_cubed = m(dx_squared, dx)
        v = m(x, dx_squared)
        new_x = s(s(m(dy, dy), dx_cubed), a(v, v))
        new_y = s(m(dy, s(v, new_x)), m(y, dx_cubed))
        new_z = m(z, dx)

        line = None
        if evaluation_point is not None:
            # The evaluation is scaled by (x2*Z²-X)*Z³ in Fp2.
            line = self.line_at(
                s(m(dy, x), m(dx, y)),
                m(dy, z_squared), m(new_z, z_squared), evaluation_point,
            )
        return (red(new_x), red(new_y), red(new_z)), line

    def line_at(self, intercept, gradient, scale, affine):
        tower = self.curve.tower
        fp = self.curve.field
        x, y = affine
        return tuple(tower.normalize(coefficient) for coefficient in (
            intercept, tower.scale(gradient, fp.sub(0, x)), tower.scale(scale, y),
        ))

    def require_affine(self, point, affine):
        x, y, z = point
        m = self.curve.mul
        if self.curve.twist:
            first, second = map(self.curve.field.nonzero, z)
            self.curve.field.require(self.curve.field.add(first, second))
        else:
            self.curve.field.require(self.curve.field.nonzero(z))
        z_squared = m(z, z)
        self.curve.equal(x, m(affine[0], z_squared))
        self.curve.equal(y, m(affine[1], m(z, z_squared)))

"""BLS12-381 field formulas shared by the script generator and witness builder."""

from math import gcd

Q = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
U = 0xD201000000010000  # Absolute value of the negative BLS12-381 seed.
R = U**4 - U**2 + 1
EXTENSION_ORDER = Q**12 - 1
QUOTIENT_ORDER = Q**6 + 1
RESIDUE_EXPONENT = Q + U
assert gcd(RESIDUE_EXPONENT, QUOTIENT_ORDER) == R
RESIDUE_INVERSE = pow(RESIDUE_EXPONENT, -1, QUOTIENT_ORDER // R)
BETA = pow(2, (Q - 1) // 3, Q)


class PrimeField:
    def add(self, a, b):
        return a + b

    def sub(self, a, b):
        return a - b

    def mul(self, a, b):
        return a * b

    def reduce(self, a):
        return a % Q

    def nonzero(self, a):
        return a % Q != 0

    def require(self, condition):
        if not condition:
            raise ValueError("invalid field relation")

    def inverse(self, a):
        return pow(a, -1, Q)

    def hint(self, a):
        return a


class Tower:
    """i² = -1, w⁶ = 1+i. Coefficients of w are in ascending order."""

    def __init__(self, fp):
        self.fp = fp

    def add(self, a, b):
        return tuple(self.fp.add(x, y) for x, y in zip(a, b, strict=True))

    def sub(self, a, b):
        return tuple(self.fp.sub(x, y) for x, y in zip(a, b, strict=True))

    def scale(self, a, b):
        return tuple(self.fp.mul(x, b) for x in a)

    def normalize(self, a):
        return tuple(self.fp.reduce(x) for x in a)

    def nonresidue(self, a):
        real, imag = a
        return self.fp.sub(real, imag), self.fp.add(real, imag)

    def mul2(self, a, b):
        if a == b:
            real = self.fp.mul(self.fp.add(a[0], a[1]), self.fp.sub(a[0], a[1]))
            cross = self.fp.mul(a[0], a[1])
            return real, self.fp.add(cross, cross)
        ac = self.fp.mul(a[0], b[0])
        bd = self.fp.mul(a[1], b[1])
        cross = self.fp.mul(self.fp.add(a[0], a[1]), self.fp.add(b[0], b[1]))
        return self.fp.sub(ac, bd), self.fp.sub(self.fp.sub(cross, ac), bd)

    def inverse2(self, a):
        real, imag = a
        inverse = self.fp.inverse(real * real + imag * imag)
        return (real * inverse % Q, -imag * inverse % Q)

    def power2(self, a, exponent):
        value = (1, 0)
        for bit in bin(exponent)[2:]:
            value = self.normalize(self.mul2(value, value))
            if bit == "1":
                value = self.normalize(self.mul2(value, a))
        return value

    def mul6(self, a, b):
        """Cubic Karatsuba, with v=w² and v³=1+i."""
        a0, a1, a2 = a
        b0, b1, b2 = b
        p0 = self.mul2(a0, b0)
        p1 = self.mul2(a1, b1)
        p2 = self.mul2(a2, b2)
        c01 = self.sub(self.sub(self.mul2(self.add(a0, a1), self.add(b0, b1)), p0), p1)
        c02 = self.sub(self.sub(self.mul2(self.add(a0, a2), self.add(b0, b2)), p0), p2)
        c12 = self.sub(self.sub(self.mul2(self.add(a1, a2), self.add(b1, b2)), p1), p2)
        return self.add(p0, self.nonresidue(c12)), self.add(c01, self.nonresidue(p2)), self.add(c02, p1)

    def mul_v(self, a):
        return self.nonresidue(a[2]), a[0], a[1]

    def mul12(self, a, b):
        even, odd = a[::2], a[1::2]
        even_b, odd_b = b[::2], b[1::2]
        if a == b:
            # Quadratic extension squaring using two cubic multiplications.
            cross = self.mul6(even, odd)
            both = self.mul6(self.add6(even, odd), self.add6(even, self.mul_v(odd)))
            left = self.sub6(self.sub6(both, cross), self.mul_v(cross))
            right = self.add6(cross, cross)
        else:
            ab = self.mul6(even, even_b)
            cd = self.mul6(odd, odd_b)
            both = self.mul6(self.add6(even, odd), self.add6(even_b, odd_b))
            left = self.add6(ab, self.mul_v(cd))
            right = self.sub6(self.sub6(both, ab), cd)
        return tuple(self.normalize(x) for pair in zip(left, right, strict=True) for x in pair)

    def add6(self, a, b):
        return tuple(self.add(x, y) for x, y in zip(a, b, strict=True))

    def sub6(self, a, b):
        return tuple(self.sub(x, y) for x, y in zip(a, b, strict=True))

    def mul_line(self, a, line):
        """Multiply by a Miller line with nonzero slots 0, 2 and 3."""
        result = [(0, 0)] * 6
        for i, term in enumerate(a):
            for j, coefficient in zip((0, 2, 3), line, strict=True):
                product = self.mul2(term, coefficient)
                if i + j >= 6:
                    product = self.nonresidue(product)
                index = (i + j) % 6
                result[index] = self.add(result[index], product)
        return tuple(self.normalize(x) for x in result)

    def join_lines(self, left, right):
        """Multiply two sparse lines with six Fp2 multiplications."""
        left0, left2, left3 = left
        right0, right2, right3 = right
        p0 = self.mul2(left0, right0)
        p2 = self.mul2(left2, right2)
        p3 = self.mul2(left3, right3)

        def cross(a, b, c, d, first, second):
            total = self.mul2(self.add(a, b), self.add(c, d))
            return self.sub(self.sub(total, first), second)

        return (
            self.add(p0, self.nonresidue(p3)),
            (0, 0),
            cross(left0, left2, right0, right2, p0, p2),
            cross(left0, left3, right0, right3, p0, p3),
            p2,
            cross(left2, left3, right2, right3, p2, p3),
        )

    def power12(self, a, exponent):
        value = ONE
        for bit in bin(exponent)[2:]:
            value = self.mul12(value, value)
            if bit == "1":
                value = self.mul12(value, a)
        return value

    def frobenius(self, a):
        return tuple(
            self.normalize(self.mul2((real, self.fp.sub(0, imag)), factor))
            for (real, imag), factor in zip(a, FROBENIUS, strict=True)
        )


ONE = ((1, 0),) + ((0, 0),) * 5
_field = Tower(PrimeField())
_frobenius_w = _field.power2((1, 1), (Q - 1) // 6)
FROBENIUS = tuple(_field.power2(_frobenius_w, i) for i in range(6))
PSI_X = _field.inverse2(FROBENIUS[2])
PSI_Y = _field.inverse2(FROBENIUS[3])

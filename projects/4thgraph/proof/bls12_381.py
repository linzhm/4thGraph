"""BLS12-381 arithmetic shared by the host and the Script code generator."""

from functools import cache

from shared.script import asm, number
from stack_schedule import Graph

U = 0xd201000000010000  # Absolute value of the negative BLS12-381 seed.
R = U**4 - U**2 + 1
Q = (U + 1)**2 * R // 3 - U
ZERO2, ONE2 = (0, 0), (1, 0)
ONE12 = ((ONE2, ZERO2, ZERO2), (ZERO2, ZERO2, ZERO2))


class HostField:
    @staticmethod
    def add(a, b):
        return (a + b) % Q

    @staticmethod
    def sub(a, b):
        return (a - b) % Q

    @staticmethod
    def mul(a, b):
        return a * b % Q

    @staticmethod
    def reduce(a):
        return a % Q


@cache
def opcode(name):
    return asm(name)


class ScriptField:
    """Signed residues are sufficient at arithmetic boundaries inside Script."""

    def __init__(self, inputs):
        self.graph = Graph(inputs)
        self.valid = 1

    def value(self, a):
        return self.graph.define(number(a)) if type(a) is int else a

    def op(self, name, *args):
        return self.graph.define(opcode(name), tuple(map(self.value, args)))

    def add(self, a, b):
        if type(a) is type(b) is int:
            return HostField.add(a, b)
        if a == 0:
            return b
        if b == 0:
            return a
        return self.op("OP_ADD", a, b)

    def sub(self, a, b):
        if type(a) is type(b) is int:
            return HostField.sub(a, b)
        if a == b:
            return 0
        if b == 0:
            return a
        if a == 0:
            return self.op("OP_NEGATE", b)
        return self.op("OP_SUB", a, b)

    def mul(self, a, b):
        if type(a) is type(b) is int:
            return HostField.mul(a, b)
        if a == 0 or b == 0:
            return 0
        if a == 1:
            return b
        if b == 1:
            return a
        return self.op("OP_MUL", a, b)

    def reduce(self, a):
        return a % Q if type(a) is int else self.op("OP_MOD", a, Q)

    def select(self, condition, yes, no):
        if type(condition) is int:
            return yes if condition else no
        if yes == no:
            return yes
        return self.op("OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF", no, yes, condition)

    def all(self, conditions):
        for passed in conditions:
            self.valid = passed if self.valid == 1 else self.op("OP_BOOLAND", self.valid, passed)

    def equal(self, a, b):
        return self.op("OP_NOT", self.reduce(self.sub(a, b)))

    def nonzero(self, a):
        return self.op("OP_0NOTEQUAL", self.reduce(a))

    def compile(self, *, compact=False):
        return self.graph.emit((self.value(self.valid),), compact=compact)


class Tower:
    """Fp2 = Fp[i], i² = -1, Fp6 = Fp2[v], v³ = 1+i, Fp12 = Fp6[w], w² = v."""

    def __init__(self, field):
        self.fp = field

    def add2(self, a, b):
        return self.fp.add(a[0], b[0]), self.fp.add(a[1], b[1])

    def sub2(self, a, b):
        return self.fp.sub(a[0], b[0]), self.fp.sub(a[1], b[1])

    def reduce2(self, a):
        return tuple(map(self.fp.reduce, a))

    def scale2(self, a, n):
        return self.fp.mul(a[0], n), self.fp.mul(a[1], n)

    def mul2(self, a, b):
        f = self.fp
        ac, bd = f.mul(a[0], b[0]), f.mul(a[1], b[1])
        cross = f.mul(f.add(*a), f.add(*b))
        return self.reduce2((f.sub(ac, bd), f.sub(f.sub(cross, ac), bd)))

    def square2(self, a):
        f = self.fp
        return self.reduce2((f.mul(f.add(*a), f.sub(*a)), f.mul(2, f.mul(*a))))

    def xi(self, a):
        return self.fp.sub(*a), self.fp.add(*a)

    def conjugate2(self, a):
        return a[0], self.fp.sub(0, a[1])

    def add6(self, a, b):
        return tuple(self.add2(x, y) for x, y in zip(a, b, strict=True))

    def sub6(self, a, b):
        return tuple(self.sub2(x, y) for x, y in zip(a, b, strict=True))

    def mul_v(self, a):
        return self.xi(a[2]), a[0], a[1]

    def mul6(self, a, b):
        t0, t1, t2 = (self.mul2(x, y) for x, y in zip(a, b, strict=True))
        s0 = self.mul2(self.add2(a[1], a[2]), self.add2(b[1], b[2]))
        s1 = self.mul2(self.add2(a[0], a[1]), self.add2(b[0], b[1]))
        s2 = self.mul2(self.add2(a[0], a[2]), self.add2(b[0], b[2]))
        return (
            self.add2(t0, self.xi(self.sub2(self.sub2(s0, t1), t2))),
            self.add2(self.xi(t2), self.sub2(self.sub2(s1, t0), t1)),
            self.add2(t1, self.sub2(self.sub2(s2, t0), t2)),
        )

    def mul12(self, a, b):
        t0, t1 = self.mul6(a[0], b[0]), self.mul6(a[1], b[1])
        cross = self.mul6(self.add6(*a), self.add6(*b))
        return self.add6(t0, self.mul_v(t1)), self.sub6(self.sub6(cross, t0), t1)

    def square12(self, a):
        even, odd = a
        cross = self.mul6(even, odd)
        product = self.mul6(self.add6(even, odd), self.add6(even, self.mul_v(odd)))
        return self.sub6(self.sub6(product, cross), self.mul_v(cross)), self.add6(cross, cross)

    def mul_line(self, a, line):
        c0, c2, c3 = line
        even, odd = a
        t0 = self.mul6(even, (c0, c2, ZERO2))
        t1 = self.mul_v(tuple(self.mul2(coefficient, c3) for coefficient in odd))
        cross = self.mul6(self.add6(even, odd), (c0, self.add2(c2, c3), ZERO2))
        return self.add6(t0, self.mul_v(t1)), self.sub6(self.sub6(cross, t0), t1)

    def frobenius12(self, a):
        return tuple(
            tuple(self.mul2(self.conjugate2(coefficient), FROBENIUS[2 * index + parity])
                  for index, coefficient in enumerate(part))
            for parity, part in enumerate(a)
        )

    def power12(self, value, exponent):
        result = ONE12
        for bit in bin(exponent)[2:]:
            result = self.square12(result)
            if bit == "1":
                result = self.mul12(result, value)
        return result


HOST = Tower(HostField())


def power2(value, exponent):
    result = ONE2
    for bit in bin(exponent)[2:]:
        result = HOST.square2(result)
        if bit == "1":
            result = HOST.mul2(result, value)
    return result


FROBENIUS = tuple(power2((1, 1), (Q - 1) * degree // 6) for degree in range(6))
PSI_X = power2((1, 1), (1 - Q) // 3 % (Q**2 - 1))
PSI_Y = power2((1, 1), (1 - Q) // 2 % (Q**2 - 1))
# The nontrivial cube root for which phi(P) = -[U²]P on G1.
BETA = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe

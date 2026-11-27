"""A neutral two-call-site fixture with an independent affine oracle."""

from pathlib import Path

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import SECP256K1_FIELD as FIELD, asm, decode_num, encode_num, number
from fourthgraph.compiler.point_add import PointAddBuilder, fixed_operand
from fourthgraph.compiler.source import evaluate as evaluate_forth


def affine_add(left, right):
    if left is None or right is None:
        return right if left is None else left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % FIELD == 0:
            return None
        slope = 3 * x1 * x1 * pow(2 * y1, -1, FIELD) % FIELD
    else:
        slope = (y2-y1)*pow(x2-x1, -1, FIELD) % FIELD
    x = (slope * slope - x1 - x2) % FIELD
    return x, (slope * (x1 - x) - y1) % FIELD


def homogeneous(point, z):
    return (0, 1, 0) if point is None else (point[0] * z % FIELD, point[1] * z % FIELD, z)


def affine(coords):
    x, y, z = (item % FIELD for item in coords)
    if z:
        inverse = pow(z, -1, FIELD)
        return x * inverse % FIELD, y * inverse % FIELD
    if x or not y:
        raise ValueError("noncanonical point at infinity")
    return None


class PointAddFixture:
    name = "point-add"
    entry = "add-two"
    implementations = (name,)

    def __init__(self):
        self.source_bytes = (Path(__file__).with_name("fixtures") / "point-add.fth").read_bytes()
        builder = self.builder(self.source_bytes)
        encoded, = evaluate_forth(builder.words["fixed-generator"])
        self.generator = fixed_operand(encoded)

    def source(self, implementation):
        if implementation != self.name:
            raise ValueError("point-add has one frozen caller")
        return self.source_bytes

    @staticmethod
    def builder(source):
        return PointAddBuilder(source.decode())

    def vectors(self):
        g = self.generator
        inverse = (g[0], -g[1] % FIELD)
        double = affine_add(g, g)
        projective = ((None, None), (None, g), (g, None), (inverse, None), (None, inverse),
                      (g, g), (double, inverse), (inverse, g), (g, double))
        boundary = ((None, g, 1), (None, inverse, 1), (inverse, g, 1), (g, double, 2))
        for left, right, z in (*((left, right, 11) for left, right in projective), *boundary):
            yield (FIELD, *homogeneous(left, 5), *homogeneous(right, z)), affine_add(affine_add(left, g), right)

    def wrong(self, operands):
        left = affine_add(affine(operands[1:4]), self.generator)
        return operands[:1] + homogeneous(left, 5) + operands[4:]

    def check(self, script):
        main_peak = alt_peak = 0
        marker = b"caller"
        code = asm("OP_TOALTSTACK") + script

        def observe(main, alt):
            nonlocal main_peak, alt_peak
            main_peak, alt_peak = max(main_peak, len(main)), max(alt_peak, len(alt))

        passed = 0
        for operands, expected in self.vectors():
            field, *args = list(map(encode_num, operands))
            try:
                main, alt = evaluate(code, [field, marker, *args, marker], observe_stack=observe)
                if len(main) != 5 or main[:2] != [field, marker] or alt != [marker]:
                    raise ValueError("caller stack contract differs")
                if affine(tuple(map(decode_num, main[2:]))) != expected:
                    raise ValueError("result differs from the independent group oracle")
            except (ValueError, IndexError) as exc:
                return {"status": "failed", "passed": passed, "vector": operands, "diagnostic": str(exc)}
            passed += 1
        return {"status": "passed", "passed": passed, "main_peak_items": main_peak, "alt_peak_items": alt_peak}

    @staticmethod
    def result_checks(expected):
        # After the caller runs the stack holds p, X, Y, Z.
        reduce = number(FIELD) + asm("OP_MOD")
        zero = reduce + asm("OP_0 OP_NUMEQUALVERIFY")
        nonzero = reduce + asm("OP_0NOTEQUAL OP_VERIFY")
        if expected is None:
            return zero + nonzero + zero + asm("OP_DROP OP_1")
        x, y = expected
        return (asm("OP_DUP") + nonzero
                + asm("OP_DUP") + number(y) + asm("OP_MUL OP_ROT OP_SUB") + zero
                + number(x) + asm("OP_MUL OP_SUB") + zero + asm("OP_DROP OP_1"))

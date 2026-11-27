"""Frozen formula contracts; candidates supply only an implementation or pass plan."""

from dataclasses import dataclass
from itertools import product
from pathlib import Path
from random import Random

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, encode_num


MATRIX_MIN, MATRIX_MAX = -(2**255), 2**255 - 1


def matrix_product(operands):
    return tuple(sum(operands[2*row + k] * operands[4 + 2*k + column] for k in range(2))
                 for row, column in product(range(2), repeat=2))


def matrix_vectors():
    edges = (MATRIX_MIN, -1, 0, 1, MATRIX_MAX)
    right = (MATRIX_MAX, MATRIX_MIN, -1, 1)
    for a, d in product(edges, repeat=2):
        yield (a, 0, 0, d, *right)
    yield (1, 2, 3, 4, 5, 6, 7, 8)
    yield (MATRIX_MIN,) * 8
    yield (MATRIX_MAX,) * 8
    rng = Random(42017)
    for _ in range(36):
        yield tuple(rng.randint(MATRIX_MIN, MATRIX_MAX) for _ in range(8))


@dataclass(frozen=True)
class Fixture:
    name: str
    entry: str
    implementations: tuple[str, ...]

    def source(self, implementation):
        if implementation not in self.implementations:
            raise ValueError(f"unsupported implementation {implementation!r} for {self.name}")
        return (Path(__file__).with_name("formulas") / (implementation + ".fth")).read_bytes()

    def vectors(self):
        if self.name == "square":
            for x in range(11):
                yield (x,), (x*x,)
        elif self.name == "matrix-mul":
            for operands in matrix_vectors():
                yield operands, matrix_product(operands)
        else:
            edges = (-128, -1, 0, 1, 127)
            for p0, p1, p2, t in product(edges, edges, edges, (0, 1, 8, 15, 16)):
                u = 16 - t
                yield (p0, p1, p2, t), (p0*u*u + 2*p1*t*u + p2*t*t, 2*((p1-p0)*u + (p2-p1)*t))

    def check(self, script):
        return check_outputs(self.vectors(), script, encode_num, preserve_caller=self.name != "square")


def check_outputs(vectors, script, encode, *, preserve_caller=True):
    prefix = [b"\x81"] if preserve_caller else []
    alt = [b"sentinel"] if preserve_caller else []
    code = (asm("OP_TOALTSTACK") if alt else b"") + script
    main_peak = alt_peak = payload_peak = 0

    def observe(main, spare):
        nonlocal main_peak, alt_peak, payload_peak
        main_peak = max(main_peak, len(main))
        alt_peak = max(alt_peak, len(spare))
        payload_peak = max(payload_peak, sum(map(len, main)) + sum(map(len, spare)))

    passed = 0
    for operands, expected in vectors:
        try:
            actual = evaluate(code, prefix + list(map(encode, operands)) + alt, observe_stack=observe)
            if actual != (prefix + list(map(encode, expected)), alt):
                raise ValueError("returned stack bytes differ from oracle")
        except (ValueError, IndexError) as exc:
            return {"status": "failed", "passed": passed, "vector": operands, "diagnostic": str(exc)}
        passed += 1
    return {"status": "passed", "passed": passed, "main_peak_items": main_peak, "alt_peak_items": alt_peak,
            "peak_payload_bytes": payload_peak}


FIXTURES = {
    "bezier": Fixture("bezier", "bezier-coordinate", ("bezier", "bezier-linear")),
    "square": Fixture("square", "square", ("square",)),
    "matrix-mul": Fixture("matrix-mul", "matrix-product-2x2", ("matrix-mul", "matrix-mul-strassen")),
}

"""Frozen formula contracts; candidates supply only an implementation or pass plan."""

from dataclasses import dataclass
from itertools import product
from pathlib import Path

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, encode_num


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
        else:
            edges = (-128, -1, 0, 1, 127)
            for p0, p1, p2, t in product(edges, edges, edges, (0, 1, 8, 15, 16)):
                u = 16 - t
                yield (p0, p1, p2, t), (p0*u*u + 2*p1*t*u + p2*t*t, 2*((p1-p0)*u + (p2-p1)*t))

    def check(self, script):
        # The Bézier fixture seeds both stacks and checks that the caller's slots survive.
        prefix = [b"\x81"] if self.name == "bezier" else []
        alt = [b"sentinel"] if prefix else []
        code = (asm("OP_TOALTSTACK") if alt else b"") + script
        peaks = [0, 0]
        def observe(main, spare):
            peaks[0] = max(peaks[0], len(main))
            peaks[1] = max(peaks[1], len(spare))
        passed = 0
        for operands, expected in self.vectors():
            try:
                actual = evaluate(code, prefix + list(map(encode_num, operands)) + alt, observe_stack=observe)
                observe(*actual)
                if actual != (prefix + list(map(encode_num, expected)), alt):
                    raise ValueError("returned stack bytes differ from oracle")
            except (ValueError, IndexError) as exc:
                return {"status": "failed", "passed": passed, "vector": operands, "diagnostic": str(exc)}
            passed += 1
        return {"status": "passed", "passed": passed, "main_peak_items": peaks[0], "alt_peak_items": peaks[1]}


FIXTURES = {
    "bezier": Fixture("bezier", "bezier-coordinate", ("bezier", "bezier-linear")),
    "square": Fixture("square", "square", ("square",)),
}

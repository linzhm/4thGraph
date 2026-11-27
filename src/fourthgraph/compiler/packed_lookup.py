"""Lower an exact-width lookup through an immutable packed byte table."""

from dataclasses import dataclass

from fourthgraph.bsv.script import asm, number, push


@dataclass(frozen=True)
class PackedLookup:
    data: bytes
    width: int

    def __post_init__(self):
        if not isinstance(self.data, bytes) or not self.data or self.width <= 0 or len(self.data) % self.width:
            raise ValueError("packed lookup data must contain whole nonempty fixed-width rows")

    @classmethod
    def from_rows(cls, rows):
        rows = tuple(rows)
        if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
            raise ValueError("a packed lookup requires equally sized nonempty rows")
        return cls(b"".join(rows), len(rows[0]))

    def emit(self, graph, index):
        """Take a minimal ScriptNum index. Out-of-range indices abort at SPLIT."""
        table = graph.define(push(self.data))
        width = number(self.width)
        code = width + asm("OP_MUL OP_SPLIT OP_NIP") + width + asm("OP_SPLIT OP_DROP")
        return graph.define(code, (table, index))

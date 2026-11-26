"""Track checked integer intervals and base stack types."""

from dataclasses import dataclass
import re

from shared.script import asm, number

if __package__:
    from .wordsets import Literal, NUMERIC_RANGES, PRIMITIVES, Primitive, U32
else:
    from wordsets import Literal, NUMERIC_RANGES, PRIMITIVES, Primitive, U32

NUMERIC_TYPES = NUMERIC_RANGES.keys() | {"script-int"}
PRIMITIVE_NAMES = {id(word): name for name, word in PRIMITIVES.items()}
ARITHMETIC = {"+", "u32+", "-", "*", "1+", "1-", "negate", "int+", "int-", "int*"}
# Signed-magnitude Script numbers up to four bytes fit every numeric operand limit.
PORTABLE_SCRIPT_INT = (1 << 31) - 1


@dataclass(frozen=True)
class Slot:
    kind: str
    bounds: tuple[int, int] | None

    @classmethod
    def of(cls, kind):
        return cls(kind, NUMERIC_RANGES.get(kind))

    @classmethod
    def literal(cls, value: Literal):
        bounds = (value.value, value.value) if isinstance(value.value, int) else None
        return cls(value.kind, bounds)

    def within(self, other):
        if self.kind != other.kind:
            return False
        if other.bounds is None:
            return True
        return (self.bounds is not None
                and other.bounds[0] <= self.bounds[0] <= self.bounds[1] <= other.bounds[1])

    def merge(self, other):
        if self.bounds is None or other.bounds is None:
            return Slot.of(self.kind)
        return Slot(self.kind, (min(self.bounds[0], other.bounds[0]), max(self.bounds[1], other.bounds[1])))

    def describe(self):
        if self.bounds is None or self.bounds == NUMERIC_RANGES.get(self.kind):
            return self.kind
        return f"{self.kind} [{self.bounds[0]}, {self.bounds[1] + 1})"


@dataclass(frozen=True)
class RangeType:
    name: str
    base: str
    lower: int
    upper: int

    @property
    def slot(self):
        return Slot(self.base, (self.lower, self.upper - 1))

    def check(self):
        def validate(value):
            if type(value) is not int or not self.lower <= value < self.upper:
                raise ValueError(f"value is out of range for {self.name}")
            return (value,)

        canonical = asm("OP_DUP OP_DUP OP_BIN2NUM OP_EQUALVERIFY")
        code = (canonical + asm("OP_DUP") + number(self.lower) + number(self.upper) + asm("OP_WITHIN OP_VERIFY"))
        return Primitive((self.base,), (self.base,), code, validate, "explicit integer range check",
                         may_fail=True, checked_bounds=self.slot.bounds)


def range_bound(token):
    prefix = {"#": (10, r"[0-9]+"), "$": (16, r"[0-9a-fA-F]+"), "%": (2, r"[01]+")}
    marked = token[0] in prefix
    base, digits = prefix.get(token[0], (10, r"[0-9]+"))
    value = token[1:] if marked else token
    if not re.fullmatch("-?" + digits, value):
        raise ValueError("expected an integer range bound")
    return int(value, base)


def raw_interval(name, args):
    if any(arg.bounds is None for arg in args):
        return None
    if name in {"1+", "1-", "negate"}:
        low, high = args[0].bounds
        if name == "negate":
            return -high, -low
        offset = 1 if name == "1+" else -1
        return low + offset, high + offset
    a, b = args[0].bounds
    c, d = args[1].bounds
    if name in {"+", "u32+", "int+"}:
        return a + c, b + d
    if name in {"-", "int-"}:
        return a - d, b - c
    corners = a * c, a * d, b * c, b * d
    return min(corners), max(corners)


def remainder_is_identity(args):
    value, divisor = args
    if value.bounds is None or divisor.bounds is None:
        return False
    low, high = value.bounds
    minimum, maximum = divisor.bounds
    return -minimum < low <= high < minimum and 0 < minimum <= maximum <= PORTABLE_SCRIPT_INT


def primitive_outputs(word, args):
    gives = tuple(map(Slot.of, word.gives))
    name = PRIMITIVE_NAMES.get(id(word))
    if word.checked_bounds is not None:
        return (Slot(gives[0].kind, word.checked_bounds),)
    if word.comparison:
        return (Slot("cell", (-1, 0)),)
    if name in {"u32>cell", "cell>int"}:
        return (Slot(gives[0].kind, args[0].bounds),)
    if name == "cell>u32" and args[0].bounds is not None:
        lo, hi = args[0].bounds
        if 0 <= lo <= hi < U32:
            return (Slot("u32", (lo, hi)),)
    if name in ARITHMETIC:
        result = Slot(gives[0].kind, raw_interval(name, args))
        if result.within(gives[0]):
            return (result,)
    if name == "int-rem" and args[1].bounds is not None and args[1].bounds[0] > 0:
        value, divisor = args
        if remainder_is_identity(args):
            return (value,)
        limit = divisor.bounds[1] - 1
        if value.bounds is None:
            return (Slot("script-int", (-limit, limit)),)
        low, high = value.bounds
        return (Slot("script-int", (max(-limit, min(low, 0)), min(limit, max(high, 0)))),)
    return gives

"""Typed stack lowering with opt-in, source-traceable Script rewrites."""

from dataclasses import asdict, dataclass, replace

from shared.script import asm

from compiler import Conditional, Located, Shuffle, Word, lower, require_script
from wordsets import CELL_SIGN, PRIMITIVES, SHUFFLES, U32, WRAP_CELL, WRAP_U32, Literal

BASELINE = "baseline"
OPTIMIZATIONS = (BASELINE, "safe")
NUMERIC_RANGES = {"cell": (-CELL_SIGN, CELL_SIGN - 1), "u32": (0, U32 - 1), "route": (0, 1)}


@dataclass(frozen=True)
class Slot:
    kind: str
    bounds: tuple[int, int] | None

    @classmethod
    def of(cls, kind):
        return cls(kind, NUMERIC_RANGES.get(kind))

    @classmethod
    def literal(cls, value):
        bounds = (value.value, value.value) if isinstance(value.value, int) else None
        return cls(value.kind, bounds)

    def merge(self, other):
        if self.bounds is None or other.bounds is None:
            return Slot.of(self.kind)
        return Slot(self.kind, (min(self.bounds[0], other.bounds[0]), max(self.bounds[1], other.bounds[1])))


@dataclass(frozen=True)
class Operation:
    source: object
    takes: tuple[Slot, ...]
    gives: tuple[Slot, ...]
    script: bytes
    literal: Literal | None = None
    comparison: bool = False
    arms: tuple[tuple, tuple] | None = None


@dataclass(frozen=True)
class Rewrite:
    rule: str
    line: int | None
    column: int | None
    inputs: tuple[Slot, ...]


@dataclass(frozen=True)
class CompiledWord:
    script: bytes
    operations: tuple[Operation, ...] = ()
    rewrites: tuple[Rewrite, ...] = ()

    def describe(self):
        return {"script_bytes": len(self.script), "rewrites": [asdict(rewrite) for rewrite in self.rewrites]}


def expanded(body):
    for entry in body:
        node = entry.instruction if isinstance(entry, Located) else entry
        if isinstance(node, Word):
            yield from expanded(node.body)
        else:
            yield node, entry.source if isinstance(entry, Located) else None


def raw_interval(name, args):
    if name == "1+":
        a, b = args[0].bounds
        return a + 1, b + 1
    if name == "1-":
        a, b = args[0].bounds
        return a - 1, b - 1
    if name == "negate":
        a, b = args[0].bounds
        return -b, -a
    a, b = args[0].bounds
    c, d = args[1].bounds
    if name in {"+", "u32+"}:
        return a + c, b + d
    if name == "-":
        return a - d, b - c
    corners = a * c, a * d, b * c, b * d
    return min(corners), max(corners)


def encoded_primitive(node, args):
    name = next((name for name, primitive in PRIMITIVES.items() if node is primitive), None)
    gives = tuple(map(Slot.of, node.gives))
    if node.comparison:
        return node.code, (Slot("cell", (-1, 0)),), None
    if name == "u32>cell":
        return node.code, (Slot("cell", args[0].bounds),), None
    if name == "cell>u32" and args[0].bounds[0] >= 0:
        if args[0].bounds[1] < U32:
            return b"", (Slot("u32", args[0].bounds),), "u32-conversion-in-range"
        return WRAP_U32, gives, "u32-remainder-nonnegative"
    if name in {"+", "-", "*", "1+", "1-", "negate", "u32+"}:
        lo, hi = raw_interval(name, args)
        result = gives[0]
        if result.bounds[0] <= lo <= hi <= result.bounds[1]:
            wrap = WRAP_CELL if result.kind == "cell" else WRAP_U32
            return node.code[:-len(wrap)], (Slot(result.kind, (lo, hi)),), "arithmetic-in-range"
    return node.code, gives, None


def build_block(body, stack, rewrites):
    code = []
    for node, source in expanded(body):
        position = (source.line, source.column) if source is not None else (None, None)
        if isinstance(node, Literal):
            slot = Slot.literal(node)
            stack.append(slot)
            code.append(Operation(source, (), (slot,), node.lower(), literal=node))
        elif isinstance(node, Shuffle):
            count, order, opcode = SHUFFLES[node.name]
            args = tuple(stack[-count:])
            outputs = tuple(args[i] for i in order)
            stack[-count:] = outputs
            code.append(Operation(source, args, outputs, asm(opcode)))
        elif isinstance(node, Conditional):
            flag = stack.pop()
            yes, no = list(stack), list(stack)
            yes_code = build_block(node.yes, yes, rewrites)
            no_code = build_block(node.no, no, rewrites)
            stack[:] = [a.merge(b) for a, b in zip(yes, no, strict=True)]
            prefix = asm("OP_0NOTEQUAL")
            if code and code[-1].comparison:
                cmp = code[-1]
                code[-1] = replace(cmp, script=cmp.script[:-1])
                prefix = b""
                rewrites.append(Rewrite("comparison-feeds-if", *position, (flag,)))
            script = (prefix + asm("OP_IF") + emit(yes_code)
                      + asm("OP_ELSE") + emit(no_code) + asm("OP_ENDIF"))
            code.append(Operation(source, (flag,), (), script, arms=(yes_code, no_code)))
        else:
            argc = len(node.takes)
            start = len(stack) - argc
            args = tuple(stack[start:])
            pushes = code[-argc:] if argc else ()
            if node.code is not None and argc and len(pushes) == argc and all(op.literal is not None for op in pushes):
                value, = node.run(*(op.literal.value for op in pushes))
                literal = Literal(node.gives[0], value)
                output = Slot.literal(literal)
                code[-argc:] = [Operation(source, (), (output,), literal.lower(), literal=literal)]
                stack[start:] = [output]
                continue
            script, outputs, rule = encoded_primitive(node, args)
            if node is PRIMITIVES["+"] or node is PRIMITIVES["u32+"]:
                if code and code[-1].literal == Literal(node.takes[-1], 1):
                    code.pop()
                    script = asm("OP_1ADD") + script[1:]
                    rewrites.append(Rewrite("add-one-instruction", *position, args))
            if rule:
                rewrites.append(Rewrite(rule, *position, args))
            stack[start:] = outputs
            code.append(Operation(source, args, outputs, script, comparison=node.comparison))
    return tuple(code)


def emit(operations):
    return b"".join(op.script for op in operations)


def compile_word(word, optimization=BASELINE):
    if optimization not in OPTIMIZATIONS:
        raise ValueError(f"unknown optimization {optimization!r}")
    require_script(word)
    if optimization == BASELINE:
        return CompiledWord(lower(word))
    rewrites = []
    operations = build_block(word.body, [Slot.of(kind) for kind in word.takes], rewrites)
    return CompiledWord(emit(operations), operations, tuple(rewrites))

"""Typed stack lowering with opt-in, source-traceable Script rewrites."""

from dataclasses import asdict, dataclass, replace

from shared.script import asm

from compiler import (
    MAX_EXPANSION, CompileError, Conditional, Shuffle, Token, check_word_expansion, entry_range_checks, expanded, lower,
    require_script,
)
from ranges import PRIMITIVE_NAMES, Slot, primitive_outputs, raw_interval, remainder_is_identity
from stack_schedule import Graph
from wordsets import NUMERIC_RANGES, PRIMITIVES, SHUFFLES, U32, WRAP_CELL, WRAP_U32, Literal

BASELINE = "baseline"
OPTIMIZATIONS = (BASELINE, "safe", "stack")


@dataclass(frozen=True)
class Operation:
    source: Token | None
    takes: tuple[Slot, ...]
    gives: tuple[Slot, ...]
    script: bytes
    depth: int
    literal: Literal | None = None
    comparison: bool = False
    total: bool = False
    permutation: tuple[int, ...] | None = None
    arms: tuple[tuple, tuple] | None = None


@dataclass(frozen=True)
class Rewrite:
    rule: str
    line: int | None
    column: int | None
    inputs: tuple[Slot, ...]
    script_bytes: tuple[int, int] | None = None
    basis: str | None = None
    module: str | None = None


@dataclass(frozen=True)
class CompiledWord:
    script: bytes
    operations: tuple[Operation, ...] = ()
    rewrites: tuple[Rewrite, ...] = ()

    def describe(self):
        rewrites = []
        for rewrite in self.rewrites:
            row = asdict(rewrite)
            if rewrite.basis is None:
                del row["basis"]
            if rewrite.module is None:
                del row["module"]
            rewrites.append(row)
        return {"script_bytes": len(self.script), "rewrites": rewrites}


def encoded_primitive(node, args):
    name = PRIMITIVE_NAMES.get(id(node))
    gives = primitive_outputs(node, args)
    if name == "cell>u32" and args[0].bounds[0] >= 0:
        if args[0].bounds[1] < U32:
            return b"", gives, "u32-conversion-in-range"
        return WRAP_U32, gives, "u32-remainder-nonnegative"
    if name in {"+", "-", "*", "1+", "1-", "negate", "u32+"}:
        lo, hi = raw_interval(name, args)
        result = gives[0]
        if result.bounds[0] <= lo <= hi <= result.bounds[1]:
            wrap = WRAP_CELL if result.kind == "cell" else WRAP_U32
            return node.code[:-len(wrap)], gives, "arithmetic-in-range"
    if name == "int-rem" and remainder_is_identity(args):
        return asm("OP_DROP"), gives, "integer-remainder-in-range"
    return node.code, gives, None


def build_block(body, stack, rewrites, *, schedule=False):
    code = []
    for node, source in expanded(body):
        depth = len(stack)
        position = (source.line, source.column) if source is not None else (None, None)
        module = source.module if source is not None else None
        if isinstance(node, Literal):
            slot = Slot.literal(node)
            stack.append(slot)
            total = isinstance(node.value, int) or len(node.value) <= 32
            code.append(Operation(source, (), (slot,), node.lower(), depth, literal=node, total=total))
        elif isinstance(node, Shuffle):
            count, order, opcode = SHUFFLES[node.name]
            args = tuple(stack[-count:])
            outputs = tuple(args[i] for i in order)
            stack[-count:] = outputs
            code.append(Operation(source, args, outputs, asm(opcode), depth, total=True, permutation=order))
        elif isinstance(node, Conditional):
            flag = stack.pop()
            yes, no = list(stack), list(stack)
            yes_code = build_block(node.yes, yes, rewrites, schedule=schedule)
            no_code = build_block(node.no, no, rewrites, schedule=schedule)
            stack[:] = [a.merge(b) for a, b in zip(yes, no, strict=True)]
            prefix = asm("OP_0NOTEQUAL")
            if code and code[-1].comparison:
                cmp = code[-1]
                code[-1] = replace(cmp, script=cmp.script[:-1])
                prefix = b""
                rewrites.append(Rewrite("comparison-feeds-if", *position, (flag,), module=module))
            script = (prefix + asm("OP_IF") + emit(yes_code)
                      + asm("OP_ELSE") + emit(no_code) + asm("OP_ENDIF"))
            code.append(Operation(source, (flag,), (), script, depth, arms=(yes_code, no_code)))
        else:
            argc = len(node.takes)
            start = len(stack) - argc
            args = tuple(stack[start:])
            pushes = code[-argc:] if argc else ()
            if (node.code is not None and not node.may_fail and argc and len(pushes) == argc
                    and all(op.literal is not None for op in pushes)):
                value, = node.run(*(op.literal.value for op in pushes))
                literal = Literal(node.gives[0], value)
                output = Slot.literal(literal)
                total = isinstance(value, int) or len(value) <= 32
                code[-argc:] = [Operation(source, (), (output,), literal.lower(), pushes[0].depth,
                                          literal=literal, total=total)]
                stack[start:] = [output]
                continue
            script, outputs, rule = encoded_primitive(node, args)
            takes = args
            if node is PRIMITIVES["+"] or node is PRIMITIVES["u32+"]:
                if code and code[-1].literal == Literal(node.takes[-1], 1):
                    code.pop()
                    depth -= 1
                    takes = args[:-1]
                    script = asm("OP_1ADD") + script[1:]
                    rewrites.append(Rewrite("add-one-instruction", *position, args, module=module))
            if rule == "integer-remainder-in-range":
                original_bytes = len(node.code)
                if code and code[-1].literal is not None:
                    original_bytes += len(code.pop().script)
                    depth -= 1
                    takes = args[:-1]
                    script = b""
                rewrites.append(Rewrite(rule, *position, args, (original_bytes, len(script)),
                                        "positive bounded divisor exceeds the dividend magnitude", module=module))
            elif rule:
                rewrites.append(Rewrite(rule, *position, args, module=module))
            stack[start:] = outputs
            # Arbitrary byte strings may exceed a Script stack resource limit
            # when used by a compound primitive. Keep their evaluation order.
            total = not node.may_fail and all(part.kind in NUMERIC_RANGES for part in (*takes, *outputs))
            code.append(Operation(source, takes, outputs, script, depth,
                                  comparison=node.comparison, total=total))
    return schedule_blocks(code, rewrites) if schedule else tuple(code)


def schedule_blocks(code, rewrites):
    result, block = [], []
    for op in code:
        if op.total:
            block.append(op)
        else:
            result.extend(schedule_block(block, rewrites))
            block.clear()
            result.append(op)
    result.extend(schedule_block(block, rewrites))
    return tuple(result)


def schedule_block(block, rewrites):
    if len(block) < 2:
        return block
    start = block[0]
    graph = Graph(start.depth)
    slots = list(graph.inputs)
    for op in block:
        assert len(slots) == op.depth
        cut = len(slots) - len(op.takes)
        operands = slots[cut:]
        if op.permutation is not None:
            slots[cut:] = [operands[i] for i in op.permutation]
        else:
            slots[cut:] = [graph.define(op.script, operands, kind=op.gives[0].kind)]
    before = sum(len(op.script) for op in block)
    script = graph.emit(slots)
    compact = graph.emit(slots, compact=True)
    if min(len(script), len(compact)) >= before:
        return block
    source = start.source
    line, column = (source.line, source.column) if source else (None, None)
    module = source.module if source else None
    if len(script) < before:
        rewrites.append(Rewrite("stack-last-use-and-sharing", line, column, (), (before, len(script)), module=module))
    if len(compact) < min(before, len(script)):
        rewrites.append(Rewrite("stack-local-operand-scheduling", line, column, (), (min(before, len(script)), len(compact)),
                                "total basic block, live-use counts, exact commutative opcode, unchanged output order",
                                module=module))
        script = compact
    return (Operation(source, (), (), script, start.depth),)


def emit(operations):
    return b"".join(op.script for op in operations)


def compile_word(word, optimization=BASELINE, *, check_input_ranges=True, max_expansion=MAX_EXPANSION):
    if optimization not in OPTIMIZATIONS:
        raise ValueError(f"unknown optimization {optimization!r}")
    if optimization == BASELINE:
        return CompiledWord(lower(word, check_input_ranges=check_input_ranges, max_expansion=max_expansion))
    require_script(word)
    check_word_expansion(word, max_expansion)
    rewrites = []
    try:
        operations = build_block(word.body, list(word.slots(word.takes)), rewrites,
                                 schedule=optimization == "stack")
    except RecursionError as error:
        raise CompileError("expanded conditional nesting exceeds the compiler's recursion limit") from error
    prefix = entry_range_checks(word) if check_input_ranges else b""
    return CompiledWord(prefix + emit(operations), operations, tuple(rewrites))

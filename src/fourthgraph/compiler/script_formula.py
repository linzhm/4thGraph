"""Compile straight-line Forth formulas over bounded Script integers."""

from collections import Counter
from dataclasses import dataclass

from fourthgraph.bsv.script import asm, number

from .source import identifier, named_token, required
from .ranges import Slot, primitive_outputs
from .stack_schedule import Graph
from .wordsets import PRIMITIVES, cell_literal

ARITHMETIC = {"int+", "int-", "int*", "int-rem"}
SYNTAX = ARITHMETIC | {"let", "int-from-bottom"}
GENESIS_NUM_BYTES = 750_000
FORMULA_PASSES = ("rewrite", "share", "stack", "search")


def validate_formula_passes(passes):
    passes = tuple(passes)
    if len(set(passes)) != len(passes) or set(passes).difference(FORMULA_PASSES):
        raise ValueError(f"unknown or repeated formula pass in {passes!r}")
    if "search" in passes and "stack" not in passes:
        raise ValueError("formula search requires stack scheduling")
    return tuple(name for name in FORMULA_PASSES if name in passes)


@dataclass(frozen=True)
class Step:
    operation: str
    bounds: Slot
    args: tuple[int, ...] = ()
    immediate: int | None = None


@dataclass(frozen=True)
class Formula:
    input_count: int
    steps: tuple[Step, ...]
    returns: tuple[int, ...]

    def bind_input(self, index, value):
        """Substitute a proven constant and remove its runtime stack slot."""
        if not 0 <= index < self.input_count:
            raise ValueError("formula input index is out of range")
        low, high = self.steps[index].bounds.bounds
        if not low <= value <= high:
            raise ValueError("constant is outside the formula input range")
        inputs = self.input_count - 1
        steps = [step for offset, step in enumerate(self.steps[:self.input_count]) if offset != index]
        slots = list(range(self.input_count))
        slots[index:] = [inputs, *range(index, inputs)]
        steps.append(Step("literal", Slot("script-int", (value, value)), immediate=value))
        for step in self.steps[self.input_count:]:
            args = tuple(slots[arg] for arg in step.args)
            if args:
                bounds, = primitive_outputs(PRIMITIVES[step.operation], tuple(steps[arg].bounds for arg in args))
                step = Step(step.operation, bounds, args)
            slots.append(len(steps))
            steps.append(step)
        return Formula(inputs, tuple(steps), tuple(slots[index] for index in self.returns))

    def lower(self, *, optimize=False, specialized=False, passes=None):
        args = self.input_count, self.steps, self.returns
        if passes is not None:
            if optimize or specialized:
                raise ValueError("explicit formula passes cannot be combined with automatic selection or specialization")
            passes = validate_formula_passes(passes)
            code, rules = emit(*args, rewrite="rewrite" in passes, share="share" in passes,
                               stack="stack" in passes, search="search" in passes)
            return code, {
                "passes": passes, "script_bytes": len(code), "rewrites": rules,
                "max_magnitude_bits": magnitude_bits(self.steps),
            }
        baseline, _ = emit(*args)
        candidates = {"baseline": (baseline, {})}
        if optimize:
            candidates["schedule"] = emit(*args, share=True, stack=True, search=True)
            candidates["rewrite-and-schedule"] = emit(
                *args, share=True, stack=True, search=True, rewrite=True, specialized=specialized,
            )
        selected = min(candidates, key=lambda name: len(candidates[name][0]))
        code, rules = candidates[selected]
        return code, {
            "selected": selected, "candidates": {name: len(result[0]) for name, result in candidates.items()},
            "rewrites": rules, "max_magnitude_bits": magnitude_bits(self.steps),
        }


def magnitude_bits(steps):
    return max(abs(bound).bit_length() for step in steps for bound in step.bounds.bounds)


def cached_integer(depth):
    decrement = asm("OP_1SUB") if depth == 0 else number(depth + 1) + asm("OP_SUB")
    return asm("OP_DEPTH") + decrement + asm("OP_PICK")


def cross_products(step, steps):
    """Recognize (a+b)*(c+d)-a*c-b*d, including either diagonal pairing."""
    if step.operation != "int-":
        return None
    first_difference, second_term = (steps[index] for index in step.args)
    if first_difference.operation != "int-" or second_term.operation != "int*":
        return None
    product, first_term = (steps[index] for index in first_difference.args)
    if product.operation != "int*" or first_term.operation != "int*":
        return None
    left, right = (steps[index] for index in product.args)
    if left.operation != "int+" or right.operation != "int+":
        return None
    a, b = left.args
    c, d = right.args
    terms = Counter(tuple(sorted(term.args)) for term in (first_term, second_term))
    for c, d in ((c, d), (d, c)):
        if terms != Counter((tuple(sorted((a, c))), tuple(sorted((b, d))))):
            continue
        pairs = ((a, d), (b, c))
        products = [primitive_outputs(PRIMITIVES["int*"], tuple(steps[index].bounds for index in pair))[0]
                    for pair in pairs]
        result, = primitive_outputs(PRIMITIVES["int+"], products)
        if all(abs(bound).bit_length() < GENESIS_NUM_BYTES * 8
               for slot in (*products, result) for bound in slot.bounds):
            return pairs
    return None


def emit(input_count, steps, returns, *, rewrite=False, share=False, stack=False, search=False,
         specialized=False):
    graph = Graph(input_count, share=share)
    values = list(graph.inputs)
    rules = Counter()

    def product(a, b):
        for constant, other in ((a, b), (b, a)):
            step = steps[constant]
            if specialized and step.operation == "literal" and step.immediate == 1:
                rules["multiply-by-one"] += 1
                return values[other]
        return graph.define(PRIMITIVES["int*"].code, (values[a], values[b]))

    for step in steps[input_count:]:
        args = tuple(values[arg] for arg in step.args)
        if step.operation == "literal":
            code = number(step.immediate)
        elif step.operation == "int-from-bottom":
            code = cached_integer(step.immediate)
        else:
            code = PRIMITIVES[step.operation].code
            left, right = (steps[index] for index in step.args)
            pairs = cross_products(step, steps) if rewrite else None
            if pairs:
                code = PRIMITIVES["int+"].code
                args = tuple(product(a, b) for a, b in pairs)
                rules["expand-cross-products"] += 1
            elif rewrite and step.operation == "int*" and any(
                    part.operation == "literal" and part.immediate == 2 for part in (left, right)):
                code = asm("OP_DUP OP_ADD")
                args = (args[1] if left.operation == "literal" and left.immediate == 2 else args[0],)
                rules["multiply-by-two-as-addition"] += 1
            elif specialized and step.operation == "int*":
                values.append(product(*step.args))
                continue
            elif rewrite and step.operation == "int-rem" and right.operation == "int-from-bottom":
                code = cached_integer(right.immediate) + code
                args = (args[0],)
                rules["fuse-cached-divisor-load"] += 1
        values.append(graph.define(code, args))
    outputs = tuple(values[result] for result in returns)
    code = (graph.search_order(outputs) if search
            else graph.emit(outputs, last_use=stack, compact=stack))
    return code, dict(rules)


def read_formula(tokens, at, ranges):
    entry = named_token(tokens, at, "formula name")
    effect = tokens.stack_effect()
    if (effect is None or effect.count("--") != 1
            or any(word not in ranges or ranges[word].base != "script-int" for word in effect if word != "--")):
        raise entry.error("expected a stack effect using declared script-int ranges")
    split = effect.index("--")
    inputs, outputs = effect[:split], effect[split + 1:]
    if not outputs:
        raise entry.error("a formula must return at least one integer")
    if required(tokens, entry, "'{:'").name != "{:":
        raise entry.error("expected '{:' before formula input names")
    locals_ = {}
    steps = [Step("input", ranges[kind].slot) for kind in inputs]
    for index in range(len(inputs)):
        local = named_token(tokens, entry, "formula input")
        if local.name in locals_ or local.name in SYNTAX:
            raise local.error(f"invalid or duplicate formula input {local.text!r}")
        locals_[local.name] = index
    if required(tokens, entry, "':}'").name != ":}":
        raise entry.error("formula input names must match the stack effect")
    stack = []
    unused = {}
    for token in tokens:
        name = token.name
        if name == ";":
            break
        if name == "let":
            local = named_token(tokens, token, "local name")
            if local.name in locals_ or local.name in SYNTAX or not stack:
                raise local.error("LET needs a stack value and a new local name")
            locals_[local.name] = stack.pop()
            unused[local.name] = local
            continue
        if name in locals_:
            stack.append(locals_[name])
            unused.pop(name, None)
            continue
        if name == "int-from-bottom":
            depth = required(tokens, token, "nonnegative stack index")
            kind = identifier(tokens, token, "cached integer range")
            if (not depth.text.isascii() or not depth.text.isdecimal() or len(depth.text) > 9
                    or kind not in ranges or ranges[kind].base != "script-int"):
                raise token.error("INT-FROM-BOTTOM requires a nonnegative stack index and a script-int range")
            step = Step(name, ranges[kind].slot, immediate=int(depth.text))
        elif name in ARITHMETIC:
            if len(stack) < 2:
                raise token.error(f"stack underflow at {token.text}")
            args = tuple(stack[-2:])
            del stack[-2:]
            slots = tuple(steps[index].bounds for index in args)
            bounds, = primitive_outputs(PRIMITIVES[name], slots)
            if bounds.bounds is None:
                raise token.error("the operation needs a proven finite range, including a positive divisor for INT-REM")
            step = Step(name, bounds, args)
        else:
            try:
                literal = cell_literal(token.text)
            except ValueError as error:
                raise token.error(str(error)) from error
            if literal is None:
                raise token.error(f"unknown formula word {token.text!r}")
            step = Step("literal", Slot("script-int", (literal.value, literal.value)), immediate=literal.value)
        stack.append(len(steps))
        steps.append(step)
    else:
        raise entry.error("unterminated formula")
    if unused:
        local = next(iter(unused.values()))
        raise local.error(f"unused formula local {local.text!r}")
    if len(stack) != len(outputs) or any(not steps[index].bounds.within(ranges[kind].slot)
                                         for index, kind in zip(stack, outputs)):
        raise entry.error("formula results do not fit the declared stack effect and ranges")
    if magnitude_bits(steps) >= GENESIS_NUM_BYTES * 8:
        raise entry.error("formula integers may exceed the BSV Genesis ScriptNum limit")
    return entry, Formula(len(inputs), tuple(steps), tuple(stack))

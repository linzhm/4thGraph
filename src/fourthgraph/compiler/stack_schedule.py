"""Schedule a straight-line graph of total operations on the Script stack."""

from collections import Counter
from dataclasses import dataclass
from heapq import nsmallest

from fourthgraph.bsv.script import asm, number

COMMUTATIVE = frozenset(map(asm, ("OP_ADD", "OP_MUL", "OP_MIN", "OP_MAX", "OP_NUMEQUAL", "OP_EQUAL")))
VERIFY = asm("OP_VERIFY")
# These pairs have the same pass/fail behavior in Genesis and Chronicle.
VERIFY_FORMS = {
    asm("OP_EQUAL"): asm("OP_EQUALVERIFY"),
    asm("OP_CHECKSIG"): asm("OP_CHECKSIGVERIFY"),
}


@dataclass(frozen=True)
class Value:
    slot: int


@dataclass(frozen=True)
class Definition:
    script: bytes
    args: tuple[Value, ...]


class Graph:
    """Inputs are ordered from bottom to top. Each operation returns one value."""

    def __init__(self, input_count, *, share=True):
        self.inputs = tuple(Value(i) for i in range(input_count))
        self.definitions = {}
        self.common = {}
        self.share = share

    def define(self, script, args=(), *, kind=None):
        if not script and len(args) == 1:
            # A representation-preserving conversion leaves the same stack slot.
            return args[0]
        node = Definition(script, tuple(args))
        key = kind, node
        if self.share and key in self.common:
            return self.common[key]
        value = Value(len(self.inputs) + len(self.definitions))
        self.definitions[value] = node
        self.common[key] = value
        return value

    def live_definitions(self, returns):
        needed = set(returns)
        for value, node in reversed(self.definitions.items()):
            if value in needed:
                needed.update(node.args)
        return [(value, node) for value, node in self.definitions.items() if value in needed]

    def emit(self, returns, *, last_use=True, compact=False, trace=None):
        return self._emit_order(self.live_definitions(returns), returns, last_use=last_use, compact=compact,
                                trace=trace)

    def emit_assertions(self, checks, *, compact=False):
        """Consume required flags at their producers in a graph of total operations."""
        checks = set(checks)
        if checks.difference(self.inputs, self.definitions):
            raise ValueError("assertion refers to an undefined graph value")
        steps = [(VERIFY, (value,), ()) for value in self.inputs if value in checks]
        for value, node in self.live_definitions(checks):
            steps.append((node.script, node.args, (value,)))
            if value in checks:
                steps.append((VERIFY, (value,), ()))
        return emit_steps(self.inputs, steps, (), compact=compact)

    def _emit_order(self, ordered, returns, *, last_use, compact, trace=None):
        uses = Counter(returns)
        uses.update(arg for _, node in ordered for arg in node.args)
        stack = Layout(self.inputs, uses)
        if trace is not None:
            trace.update(order="source", last_use=last_use, compact=compact,
                         inputs=[value.slot for value in self.inputs], returns=[value.slot for value in returns],
                         steps=[])
        for slot, node in ordered:
            record = None
            if trace is not None:
                record = {"slot": slot.slot, "args": [value.slot for value in node.args],
                          "offset": len(stack.code), "before": [value.slot for value in stack.slots]}
            stack.execute(node.script, node.args, (slot,), last_use=last_use, compact=compact, trace=record)
            if record is not None:
                record.update(bytes=len(stack.code) - record["offset"], after=[value.slot for value in stack.slots])
                trace["steps"].append(record)
        offset = len(stack.code)
        before = [value.slot for value in stack.slots] if trace is not None else None
        code = stack.finish(returns, last_use=last_use)
        if trace is not None:
            trace["finish"] = {"offset": offset, "bytes": len(code) - offset, "before": before,
                               "after": [value.slot for value in stack.slots]}
        return code

    def search_order(self, returns, *, width=96, trace=None):
        """Try alternative dependency orders for a bounded pure arithmetic graph."""
        definitions = self.live_definitions(returns)
        if len(definitions) > 128:
            code = self._emit_order(definitions, returns, last_use=True, compact=True, trace=trace)
            if trace is not None:
                trace["search"] = "graph_limit"
            return code
        source_order = self._emit_order(definitions, returns, last_use=True, compact=True)
        masks = {value: 1 << index for index, (value, _) in enumerate(definitions)}
        operations = [(masks[value], sum(masks.get(arg, 0) for arg in set(node.args)), value, node)
                      for value, node in definitions]
        uses = Counter(returns)
        uses.update(arg for _, node in definitions for arg in node.args)
        beam = [(0, Layout(self.inputs, uses), ())]
        for _ in operations:
            candidates = {}
            for done, stack, path in beam:
                for flag, dependencies, value, node in operations:
                    if done & flag or dependencies & ~done:
                        continue
                    candidate = Layout(stack.slots, stack.uses.copy())
                    candidate.execute(node.script, node.args, (value,), last_use=True, compact=True)
                    candidate.code = stack.code + candidate.code
                    state = done | flag, tuple(candidate.slots)
                    previous = candidates.get(state)
                    if previous is None or len(candidate.code) < len(previous[0].code):
                        candidates[state] = (candidate, (*path, value) if trace is not None else ())
            best = nsmallest(width, candidates.items(),
                             key=lambda entry: (len(entry[1][0].code), len(entry[1][0].slots)))
            beam = [(done, stack, path) for (done, _), (stack, path) in best]
        schedules = ((stack.finish(returns, last_use=True), path) for _, stack, path in beam)
        code, chosen = min(((source_order, None), *schedules), key=lambda entry: len(entry[0]))
        if trace is not None:
            # Trace only the selected order. Re-emit it with the same layout rules to
            # avoid storing stack snapshots for each losing beam candidate.
            ordered = definitions if chosen is None else [(value, self.definitions[value]) for value in chosen]
            traced = self._emit_order(ordered, returns, last_use=True, compact=True, trace=trace)
            if traced != code:
                raise AssertionError("traced stack order does not reproduce the selected Script")
            trace.update(order="source" if chosen is None else "beam", search="completed")
        return code


def fuse_verifications(steps, uses):
    fused = []
    for script, args, results in steps:
        if script == VERIFY and len(args) == 1 and not results and fused:
            previous, operands, flag = fused[-1]
            if flag == args and uses[args[0]] == 1 and previous in VERIFY_FORMS:
                fused[-1] = (VERIFY_FORMS[previous], operands, ())
                continue
        fused.append((script, args, results))
    return fused


def emit_steps(inputs, steps, returns, *, last_use=True, compact=False):
    """Schedule already ordered operations with any number of results."""
    uses = Counter(returns)
    uses.update(arg for _, args, _ in steps for arg in args)
    stack = Layout(inputs, uses)
    for script, args, results in fuse_verifications(steps, uses):
        stack.execute(script, args, results, last_use=last_use, compact=compact)
    return stack.finish(returns, last_use=last_use)


class Layout:
    def __init__(self, inputs, uses):
        self.slots = list(inputs)
        self.uses = uses
        self.code = bytearray()

    def execute(self, script, args, results, *, last_use, compact, trace=None):
        if compact and last_use and 0 < len(args) <= 2:
            self.arrange(args, commutative=script in COMMUTATIVE)
        else:
            for staged, operand in enumerate(args):
                self.access(operand, staged, last_use=last_use)
        if trace is not None:
            trace["operation_offset"] = len(self.code)
            trace["operands"] = [value.slot for value in self.slots[-len(args):]] if args else []
        if args:
            del self.slots[-len(args):]
        self.code.extend(script)
        self.slots.extend(results)

    def finish(self, returns, *, last_use):
        if tuple(self.slots) != tuple(returns):
            for staged, result in enumerate(returns):
                self.access(result, staged, last_use=last_use)
            for _ in range(len(self.slots) - len(returns)):
                self.discard(len(returns))
        return bytes(self.code)

    def access(self, value, staged, *, last_use):
        # Operands already brought to the top are consumed by the instruction.
        # They cannot be reused as the original slot of another operand.
        ready = len(self.slots) - staged
        index = max(i for i in range(ready) if self.slots[i] == value)
        depth = len(self.slots) - index - 1
        self.uses[value] -= 1
        if self.uses[value] == 0 and last_use:
            self.move(depth)
        else:
            self.copy(depth)
        self.slots.append(value)

    def arrange(self, args, *, commutative=False):
        # Try reusing a suffix in place only when consuming those slots
        # accounts for every remaining use of the staged values.
        orders = (args, args[::-1]) if commutative and len(args) == 2 and args[0] != args[1] else (args,)
        candidates = []
        # Trying an operand arrangement only consumes these operands. Copying
        # the full liveness table for each attempt makes large kernels
        # quadratic in the number of operations.
        uses = Counter({operand: self.uses[operand] for operand in args})
        for order in orders:
            for staged in range(len(order) + 1):
                prefix = order[:staged]
                if staged and (tuple(self.slots[-staged:]) != prefix
                               or any(self.uses[value] != count for value, count in Counter(prefix).items())):
                    continue
                candidate = Layout(self.slots, uses.copy())
                candidate.uses.subtract(prefix)
                for index in range(staged, len(order)):
                    candidate.access(order[index], index, last_use=True)
                candidates.append(candidate)
            if len(order) == 2:
                paired = self.pair(order, uses)
                if paired is not None:
                    candidates.append(paired)
        best = min(candidates, key=lambda candidate: len(candidate.code))
        self.slots = best.slots
        for operand in uses:
            self.uses[operand] = best.uses[operand]
        self.code.extend(best.code)

    def pair(self, args, uses):
        counts = Counter(args)
        if tuple(self.slots[-2:]) == args and all(uses[value] > count for value, count in counts.items()):
            candidate = Layout((*self.slots, *args), uses.copy())
            candidate.code.extend(asm("OP_2DUP"))
        elif (len(self.slots) >= 4 and tuple(self.slots[-4:-2]) == args
              and all(uses[value] == count for value, count in counts.items())):
            candidate = Layout((*self.slots[:-4], *self.slots[-2:], *args), uses.copy())
            candidate.code.extend(asm("OP_2SWAP"))
        else:
            return None
        candidate.uses.subtract(args)
        return candidate

    def move(self, depth):
        if depth < 3:
            self.code.extend(asm(("", "OP_SWAP", "OP_ROT")[depth]))
        else:
            self.code.extend(number(depth) + asm("OP_ROLL"))
        self.slots.pop(-depth - 1)

    def copy(self, depth):
        if depth < 2:
            self.code.extend(asm(("OP_DUP", "OP_OVER")[depth]))
        else:
            self.code.extend(number(depth) + asm("OP_PICK"))

    def discard(self, depth):
        if depth < 2:
            self.code.extend(asm(("OP_DROP", "OP_NIP")[depth]))
            self.slots.pop(-depth - 1)
        else:
            self.move(depth)
            self.code.extend(asm("OP_DROP"))

"""Schedule a straight-line graph of total operations on the Script stack."""

from collections import Counter
from dataclasses import dataclass
from heapq import nsmallest

from fourthgraph.bsv.script import asm, number

COMMUTATIVE = frozenset(map(asm, ("OP_ADD", "OP_MUL", "OP_MIN", "OP_MAX", "OP_NUMEQUAL", "OP_EQUAL")))


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

    def emit(self, returns, *, last_use=True, compact=False):
        live = self.live_definitions(returns)
        uses = Counter(returns)
        uses.update(arg for _, node in live for arg in node.args)
        stack = Layout(self.inputs, uses)
        for slot, node in live:
            stack.execute(slot, node, last_use=last_use, compact=compact)
        return stack.finish(returns, last_use=last_use)

    def search_order(self, returns, *, width=96):
        """Try alternative dependency orders for a bounded pure arithmetic graph."""
        source_order = self.emit(returns, compact=True)
        definitions = self.live_definitions(returns)
        if len(definitions) > 128:
            return source_order
        masks = {value: 1 << index for index, (value, _) in enumerate(definitions)}
        operations = [(masks[value], sum(masks.get(arg, 0) for arg in set(node.args)), value, node)
                      for value, node in definitions]
        uses = Counter(returns)
        uses.update(arg for _, node in definitions for arg in node.args)
        beam = [(0, Layout(self.inputs, uses))]
        for _ in operations:
            candidates = {}
            for done, stack in beam:
                for flag, dependencies, value, node in operations:
                    if done & flag or dependencies & ~done:
                        continue
                    candidate = Layout(stack.slots, stack.uses.copy())
                    candidate.execute(value, node, last_use=True, compact=True)
                    candidate.code = stack.code + candidate.code
                    state = done | flag, tuple(candidate.slots)
                    previous = candidates.get(state)
                    if previous is None or len(candidate.code) < len(previous.code):
                        candidates[state] = candidate
            best = nsmallest(width, candidates.items(),
                             key=lambda entry: (len(entry[1].code), len(entry[1].slots)))
            beam = [(done, stack) for (done, _), stack in best]
        return min((source_order, *(stack.finish(returns, last_use=True) for _, stack in beam)), key=len)


class Layout:
    def __init__(self, inputs, uses):
        self.slots = list(inputs)
        self.uses = uses
        self.code = bytearray()

    def execute(self, slot, node, *, last_use, compact):
        if compact and last_use and 0 < len(node.args) <= 2:
            self.arrange(node.args, commutative=node.script in COMMUTATIVE)
        else:
            for staged, operand in enumerate(node.args):
                self.access(operand, staged, last_use=last_use)
        if node.args:
            del self.slots[-len(node.args):]
        self.code.extend(node.script)
        self.slots.append(slot)

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

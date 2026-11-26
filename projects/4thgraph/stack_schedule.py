"""Schedule a straight-line graph of total operations on the Script stack."""

from collections import Counter
from dataclasses import dataclass

from shared.script import asm, number

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

    def emit(self, returns, *, last_use=True, compact=False):
        needed = set(returns)
        for value, node in reversed(self.definitions.items()):
            if value in needed:
                needed.update(node.args)
        live = [(value, node) for value, node in self.definitions.items() if value in needed]
        uses = Counter(returns)
        uses.update(arg for _, node in live for arg in node.args)
        stack = Layout(self.inputs, uses)
        for slot, node in live:
            if compact and last_use and 0 < len(node.args) <= 2:
                stack.arrange(node.args, commutative=node.script in COMMUTATIVE)
            else:
                for staged, operand in enumerate(node.args):
                    stack.access(operand, staged, last_use=last_use)
            if node.args:
                del stack.slots[-len(node.args):]
            stack.code.extend(node.script)
            stack.slots.append(slot)
        if tuple(stack.slots) != tuple(returns):
            for staged, result in enumerate(returns):
                stack.access(result, staged, last_use=last_use)
            for _ in range(len(stack.slots) - len(returns)):
                stack.discard(len(returns))
        return bytes(stack.code)


class Layout:
    def __init__(self, inputs, uses):
        self.slots = list(inputs)
        self.uses = uses
        self.code = bytearray()

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

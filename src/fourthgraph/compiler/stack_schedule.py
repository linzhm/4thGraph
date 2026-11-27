"""Schedule a straight-line graph of total operations on the Script stack."""

from collections import Counter
from dataclasses import dataclass
from heapq import nsmallest

from fourthgraph.bsv.script import asm, number

COMMUTATIVE = frozenset(map(asm, ("OP_ADD", "OP_MUL", "OP_MIN", "OP_MAX", "OP_NUMEQUAL", "OP_EQUAL")))
VERIFY = asm("OP_VERIFY")
REMAINDER = asm("OP_MOD")
SINGLE_BYTE_NUMBERS = frozenset(number(value) for value in range(-1, 17))
POLYNOMIAL_ARITIES = {asm(name): arity for name, arity in (
    ("OP_ADD", 2), ("OP_SUB", 2), ("OP_MUL", 2), ("OP_NEGATE", 1), ("OP_2MUL", 1),
)}
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


@dataclass(frozen=True)
class PacketSlice:
    offset: int
    width: int
    decode: bytes
    chronicle: bool

    def emit(self, position=0, *, keep_tail=False):
        skip = self.offset - position
        width = number(self.width)
        if not keep_tail and self.chronicle:
            read = number(skip) + width + asm("OP_SUBSTR") if skip else width + asm("OP_LEFT")
        else:
            prefix = number(skip) + asm("OP_SPLIT OP_NIP") if skip else b""
            read = prefix + width + asm("OP_SPLIT OP_SWAP" if keep_tail else "OP_SPLIT OP_DROP")
        return read + self.decode


class Graph:
    """Inputs are ordered from bottom to top. Each operation returns one value."""

    def __init__(self, input_count, *, share=True):
        self.inputs = tuple(Value(i) for i in range(input_count))
        self.definitions = {}
        self.common = {}
        self.packet_reads = {}
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

    def integer(self, value):
        return self.define(number(value))

    def packet_slice(self, packet, offset, width, *, decode=b"", chronicle=False):
        """Read a fixed slice of a size-checked packet.

        The decoder consumes that slice alone and returns one value.
        """
        if offset < 0 or width <= 0:
            raise ValueError("a packet slice requires a nonnegative offset and a positive width")
        read = PacketSlice(offset, width, decode, chronicle)
        value = self.define(read.emit(), (packet,), kind=read)
        self.packet_reads[value] = read
        return value

    def remainder(self, dividend, divisor, *, reuse=False):
        if reuse:
            previous = self.definitions.get(dividend)
            if previous is not None and previous.script == REMAINDER and previous.args[1:] == (divisor,):
                return dividend
        return self.define(REMAINDER, (dividend, divisor))

    def residue_block(self, modulus):
        """Lower a bounded polynomial that exposes outputs only modulo a positive integer."""
        return ResidueBlock(self, modulus)

    def live_definitions(self, returns):
        needed = set(returns)
        for value, node in reversed(self.definitions.items()):
            if value in needed:
                needed.update(node.args)
        return [(value, node) for value, node in self.definitions.items() if value in needed]

    def emit(self, returns, *, last_use=True, compact=False, trace=None):
        return self._emit_order(self.live_definitions(returns), returns, last_use=last_use, compact=compact,
                                trace=trace)

    def emit_assertions(self, checks, *, compact=False, reorder=False):
        """Consume required flags in source order.

        Reordering requires that each operation be total and observe only
        its explicit operands. Keep the shorter of the two schedules.
        """
        checks = set(checks)
        if checks.difference(self.inputs, self.definitions):
            raise ValueError("assertion refers to an undefined graph value")
        steps = [(VERIFY, (value,), ()) for value in self.inputs if value in checks]
        for value, node in self.live_definitions(checks):
            steps.append((node.script, node.args, (value,)))
            if value in checks:
                steps.append((VERIFY, (value,), ()))
        if compact and self.packet_reads:
            steps = self._stream_packet_reads(steps)
        source = emit_steps(self.inputs, steps, (), compact=compact)
        if not reorder:
            return source
        steps = list(self._assertion_dependencies(checks))
        if compact and self.packet_reads:
            steps = self._stream_packet_reads(steps)
        dependencies = emit_steps(self.inputs, steps, (), compact=compact)
        return min(source, dependencies, key=len)

    def _stream_packet_reads(self, steps):
        uses = Counter(arg for _, args, _ in steps for arg in args)
        reads = {}
        for _, args, results in steps:
            read = self.packet_reads.get(results[0]) if results else None
            if read is not None:
                packet, = args
                end, count, _ = reads.get(packet, (0, 0, None))
                if read.offset >= end:
                    reads[packet] = (read.offset + read.width, count + 1, results[0])
        # The unread suffix replaces the original packet only when every live
        # use is a slice, and those slices consume disjoint ranges in order.
        tails = {packet: (packet, 0) for packet, (_, count, _) in reads.items()
                 if count > 1 and uses[packet] == count}
        if not tails:
            return steps

        lowered = []
        next_slot = len(self.inputs) + len(self.definitions)
        for script, args, results in steps:
            read = self.packet_reads.get(results[0]) if results else None
            if read is not None and args[0] in tails:
                packet, = args
                tail, position = tails[packet]
                args = (tail,)
                keep_tail = results[0] != reads[packet][2]
                script = read.emit(position, keep_tail=keep_tail)
                if keep_tail:
                    remainder = Value(next_slot)
                    next_slot += 1
                    tails[packet] = (remainder, read.offset + read.width)
                    results = (remainder, *results)
            lowered.append((script, args, results))
        return lowered

    def _assertion_dependencies(self, checks):
        emitted = set(self.inputs)
        for check in sorted(checks, key=lambda value: value.slot):
            pending = [(check, False)]
            while pending:
                value, ready = pending.pop()
                if value in emitted:
                    continue
                node = self.definitions[value]
                if ready:
                    emitted.add(value)
                    yield node.script, node.args, (value,)
                else:
                    pending.append((value, True))
                    pending.extend((operand, False) for operand in reversed(node.args) if operand not in emitted)
            yield VERIFY, (check,), ()

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


class ResidueBlock:
    """Defer same-modulus remainders in a polynomial over Script integers.

    The caller bounds the unreduced intermediates and reduces the results on
    the parent graph before exposing them. Signed representatives may change.
    """

    def __init__(self, graph, modulus):
        if type(modulus) is not int or modulus <= 0:
            raise ValueError("a residue block requires a positive integer modulus")
        self.graph = graph
        self.divisor = graph.integer(modulus)

    def integer(self, value):
        return self.graph.integer(value)

    def define(self, script, args):
        if POLYNOMIAL_ARITIES.get(script) != len(args):
            raise ValueError("a residue block only supports polynomial arithmetic")
        return self.graph.define(script, args)

    def remainder(self, dividend, divisor, *, reuse=False):
        if divisor != self.divisor:
            raise ValueError("a residue block only supports its declared modulus")
        return dividend


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


def emit_steps(inputs, steps, returns, *, last_use=True, compact=False, trim_suffix=False, group_operands=False):
    """Schedule already ordered operations with any number of results."""
    uses = Counter(returns)
    uses.update(arg for _, args, _ in steps for arg in args)
    literals = {}
    if compact and last_use:
        returned = set(returns)
        # These pushes cost at most as much as copying one stack item.
        literals = {results[0]: script for script, args, results in steps
                    if not args and len(results) == 1 and script in SINGLE_BYTE_NUMBERS
                    and results[0] not in returned}
    stack = Layout(inputs, uses, literals=literals)
    for script, args, results in fuse_verifications(steps, uses):
        if not args and len(results) == 1 and results[0] in literals:
            continue
        stack.execute(script, args, results, last_use=last_use, compact=compact, group_operands=group_operands)
    return stack.finish(returns, last_use=last_use, trim_suffix=trim_suffix)


class Layout:
    def __init__(self, inputs, uses, *, literals=None):
        self.slots = list(inputs)
        self.uses = uses
        self.literals = literals
        self.code = bytearray()

    def execute(self, script, args, results, *, last_use, compact, trace=None, group_operands=False):
        preserved = {}
        if group_operands and last_use:
            # A result with an operand's slot ID returns that value unchanged.
            # It may move into the call even if later instructions need it again.
            preserved = {slot: self.uses[slot] - count for slot, count in Counter(args).items() if slot in results}
            self.uses.subtract(preserved)
        if compact and last_use and args and (group_operands or len(args) <= 2):
            self.arrange(args, commutative=script in COMMUTATIVE, group_operands=group_operands)
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
        self.uses.update(preserved)

    def finish(self, returns, *, last_use, trim_suffix=False):
        if tuple(self.slots) != tuple(returns):
            shorter = self.remove_dead_slots(returns) if trim_suffix else None
            start = len(self.code)
            for staged, result in enumerate(returns):
                self.access(result, staged, last_use=last_use)
            for _ in range(len(self.slots) - len(returns)):
                self.discard(len(returns))
            if shorter is not None and len(shorter) < len(self.code) - start:
                self.code[start:] = shorter
        return bytes(self.code)

    def remove_dead_slots(self, returns):
        """Preserve live values that already occur in return order."""
        wanted = set(returns)
        if tuple(slot for slot in self.slots if slot in wanted) != tuple(returns):
            return None
        first_live = next((index for index, slot in enumerate(self.slots) if slot in wanted), len(self.slots))
        if tuple(self.slots[first_live:]) == tuple(returns):
            # Park the live suffix above the caller's altstack and restore it in order.
            direct = asm("OP_2DROP") * (first_live // 2) + asm("OP_DROP") * (first_live % 2)
            return asm("OP_TOALTSTACK") * len(returns) + direct + asm("OP_FROMALTSTACK") * len(returns)
        candidate = Layout(self.slots, Counter())
        for index in range(len(self.slots) - 1, -1, -1):
            if self.slots[index] not in wanted:
                candidate.discard(len(candidate.slots) - index - 1)
        return candidate.code

    def access(self, value, staged, *, last_use):
        if self.literals and value in self.literals:
            self.code.extend(self.literals[value])
            self.uses[value] -= 1
            self.slots.append(value)
            return
        # Operands already brought to the top are consumed by the instruction.
        # They cannot be reused as the original slot of another operand.
        ready = len(self.slots) - staged
        for index in range(ready - 1, -1, -1):
            if self.slots[index] == value:
                break
        else:
            raise ValueError("operand has no unstaged stack slot")
        depth = len(self.slots) - index - 1
        self.uses[value] -= 1
        if self.uses[value] == 0 and last_use:
            self.move(depth)
        else:
            self.copy(depth)
        self.slots.append(value)

    def arrange(self, args, *, commutative=False, group_operands=False):
        if len(args) == 2:
            left, right = args
            if self.uses[left] == 1 and self.uses[right] > 1 and self.slots[-2:] == [left, right]:
                # TUCK preserves the live right operand below the ordered
                # pair. The operation consumes the other two slots.
                self.slots.insert(len(self.slots) - 2, right)
                self.uses.subtract(args)
                self.code.extend(asm("OP_TUCK"))
                return
        # Try reusing a suffix in place only when consuming those slots
        # accounts for every remaining use of the staged values.
        orders = (args, args[::-1]) if commutative and len(args) == 2 and args[0] != args[1] else (args,)
        candidates = []
        # Trying an operand arrangement only consumes these operands. Copying
        # the full liveness table for each attempt makes large kernels
        # quadratic in the number of operations.
        uses = Counter({operand: self.uses[operand] for operand in args})
        for order in orders:
            if group_operands and len(order) > 2:
                grouped = Layout(self.slots, uses.copy(), literals=self.literals)
                staged = 0
                while staged < len(order):
                    count = grouped.stage_group(order, staged)
                    if not count:
                        grouped.access(order[staged], staged, last_use=True)
                    staged += count or 1
                candidates.append(grouped)
            for staged in range(len(order) + 1):
                prefix = order[:staged]
                if staged and (tuple(self.slots[-staged:]) != prefix
                               or any(self.uses[value] != count for value, count in Counter(prefix).items())):
                    continue
                candidate = Layout(self.slots, uses.copy(), literals=self.literals)
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

    def stage_group(self, order, staged):
        """Stage a native copy or move of adjacent values wholly outside the staged suffix."""
        groups = ((3, 0, False, "OP_3DUP"), (2, 0, False, "OP_2DUP"), (2, 2, False, "OP_2OVER"),
                  (2, 2, True, "OP_2SWAP"), (2, 4, True, "OP_2ROT"))
        for count, depth, moves, opcode in groups:
            start = len(self.slots) - depth - count
            if depth < staged or start < 0 or len(order) - staged < count:
                continue
            requested = order[staged:staged + count]
            if tuple(self.slots[start:start + count]) != requested:
                continue
            uses = Counter(requested)
            if moves:
                if any(self.uses[value] != needed for value, needed in uses.items()):
                    continue
                del self.slots[start:start + count]
            elif any(self.uses[value] <= needed for value, needed in uses.items()):
                continue
            self.uses.subtract(uses)
            self.code.extend(asm(opcode))
            self.slots.extend(requested)
            return count
        return 0

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

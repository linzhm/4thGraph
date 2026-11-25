"""Compile straight-line field arithmetic into Bitcoin Script with operand liveness."""

from collections import Counter
from dataclasses import dataclass

from shared.script import asm, number

from field import Q


@dataclass(frozen=True)
class Value:
    index: int


class Program:
    def __init__(self):
        self.nodes = []
        self.inputs = []
        self.checks = []
        self.sections = {}

    def _emit(self, opcode, *operands):
        value = Value(len(self.nodes))
        self.nodes.append((opcode, operands))
        return value

    def add(self, a, b):
        if a == 0 or b == 0:
            return b if a == 0 else a
        if isinstance(a, int) and isinstance(b, int):
            return a + b
        return self._emit("ADD", a, b)

    def sub(self, a, b):
        if a == b or b == 0:
            return 0 if a == b else a
        if isinstance(a, int) and isinstance(b, int):
            return a - b
        if a == 0:
            return self._emit("NEGATE", b)
        return self._emit("SUB", a, b)

    def mul(self, a, b):
        if a == 0 or b == 0:
            return 0
        if a == 1 or b == 1:
            return b if a == 1 else a
        if isinstance(a, int) and isinstance(b, int):
            return a * b
        return self._emit("MUL", a, b)

    def divide(self, a, divisor):
        if isinstance(a, int):
            return a // divisor
        return self._emit("DIV", a, divisor)

    def less_than(self, a, limit):
        if isinstance(a, int):
            return int(a < limit)
        return self._emit("LESSTHAN", a, limit)

    def select(self, condition, when_true, when_false):
        if isinstance(condition, int):
            return when_true if condition else when_false
        if when_true == when_false:
            return when_true
        return self._emit("SELECT", when_false, when_true, condition)

    def reduce(self, a):
        if isinstance(a, int):
            return a % Q
        return self._emit("MOD", a, Q)

    def nonzero(self, a):
        if isinstance(a, int):
            return int(a % Q != 0)
        return self._emit("0NOTEQUAL", self.reduce(a))

    def require(self, condition):
        if isinstance(condition, int):
            if not condition:
                raise ValueError("invalid constant field relation")
            return
        self.checks.append(self._emit("VERIFY", condition))

    def zero(self, a):
        if isinstance(a, int):
            self.require(a % Q == 0)
        else:
            self.checks.append(self._emit("NUMEQUALVERIFY", self.reduce(a), 0))

    def wire_field(self):
        raw = self._emit("INPUT")
        self.inputs.append(raw)
        self.checks.append(value := self._emit("READ_FIELD", raw, Q))
        return value

    def mark(self, name):
        self.sections[len(self.nodes)] = name

    def compile(self, *, reuse_constants=False):
        used = Counter()
        live = set()
        pending = [*self.checks, *self.inputs]
        while pending:
            value = pending.pop()
            if value in live:
                continue
            live.add(value)
            for operand in self.nodes[value.index][1]:
                if isinstance(operand, Value):
                    used[operand] += 1
                    pending.append(operand)

        constants = ()
        if reuse_constants:
            counts = Counter(
                operand
                for index, (_, operands) in enumerate(self.nodes)
                if Value(index) in live
                for operand in operands
                if isinstance(operand, int) and operand != Q and len(number(operand)) > 16
            )
            constants = tuple(value for value, count in counts.items() if count > 1)
        resident = {Q, *constants}
        code = bytearray()
        stack = [Q, *constants, *reversed(self.inputs)]
        emit = code.extend
        emit(asm("OP_DEPTH") + number(len(self.inputs)) + asm("OP_NUMEQUALVERIFY"))
        if reuse_constants:
            # Stage the original pushes while loading constants onto the main stack.
            emit(asm("OP_TOALTSTACK") * len(self.inputs))
            emit(number(Q))
            for value in constants:
                emit(number(value))
            emit(asm("OP_FROMALTSTACK") * len(self.inputs))
        else:
            # Put the modulus beneath the proof elements without duplicating it.
            emit(number(Q))
            for _ in self.inputs:
                emit(number(len(self.inputs)) + asm("OP_ROLL"))

        boundaries = {}
        peak = len(stack)
        for index, (opcode, operands) in enumerate(self.nodes):
            if index in self.sections:
                boundaries[self.sections[index]] = len(code)
            value = Value(index)
            if value not in live or opcode == "INPUT":
                continue
            for staged, operand in enumerate(operands):
                if isinstance(operand, int) and operand not in resident:
                    emit(number(operand))
                    stack.append(operand)
                    continue
                if isinstance(operand, Value):
                    used[operand] -= 1
                consume = isinstance(operand, Value) and used[operand] == 0
                depth = next(i for i in range(staged, len(stack)) if stack[-1 - i] == operand)
                shortcut = ("", "OP_SWAP", "OP_ROT") if consume else ("OP_DUP", "OP_OVER")
                if depth < len(shortcut):
                    emit(asm(shortcut[depth]))
                else:
                    emit(number(depth) + asm("OP_ROLL" if consume else "OP_PICK"))
                if consume:
                    stack.pop(-1 - depth)
                stack.append(operand)
            peak = max(peak, len(stack))
            if opcode == "READ_FIELD":
                emit(asm("OP_SWAP OP_SIZE 49 OP_LESSTHAN OP_VERIFY OP_BIN2NUM "
                         "OP_TUCK 0 OP_ROT OP_WITHIN OP_VERIFY"))
            elif opcode == "SELECT":
                emit(asm("OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF"))
            else:
                emit(asm("OP_" + opcode))
            del stack[-len(operands):]
            if opcode not in ("VERIFY", "NUMEQUALVERIFY"):
                if used[value]:
                    stack.append(value)
                else:
                    emit(asm("OP_DROP"))
        if stack != [Q, *constants]:
            raise AssertionError("compiler left live operands on the stack")
        count = len(stack)
        emit(asm("OP_2DROP") * (count // 2))
        if count % 2:
            emit(asm("OP_DROP"))
        emit(asm("OP_1"))
        return bytes(code), boundaries, peak

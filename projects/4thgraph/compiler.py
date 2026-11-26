"""Forth 2012 Core subset, typed BSV declarations and transaction scheduling."""

from bisect import bisect_right
from dataclasses import dataclass
import re

from shared.script import asm, number
from ranges import NUMERIC_TYPES, RangeType, Slot, primitive_outputs, range_bound

from wordsets import (
    BSV_SOURCE, CORE_EXT_SCRIPT, CORE_EXT_WORDS, CORE_WORDS, HOST_WORDS, NAMED_LITERALS,
    OPTIONAL_WORDSETS, PRIMITIVES, SHUFFLES, TYPES, WRAP_U32, Literal, Primitive, cell_literal,
)

PROJECT_NAME = "4thGraph"
PROJECT_DESCRIPTION = "A Forth compiler for BSV Script and multi-transaction workflows."
PROJECT_VERSION = "0.2.0"
GATE_BOUNDARIES = ("auto", "merged", "separate")
LOCKTIME_THRESHOLD = 500_000_000


class CompileError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    text: str
    line: int
    column: int

    @property
    def name(self):
        return self.text.casefold()

    def error(self, message):
        return CompileError(f"line {self.line}, column {self.column}: {message}")


class Tokens:
    def __init__(self, source):
        self.source = source.replace("\r\n", "\n").replace("\r", "\n")
        self.offset = 0
        self.lines = [0, *(match.end() for match in re.finditer("\n", self.source))]
        self.wordsets = set()

    def __iter__(self):
        return self

    def __next__(self):
        while match := TOKEN.search(self.source, self.offset):
            self.offset = match.end()
            line = bisect_right(self.lines, match.start())
            token = Token(match[0], line, match.start() - self.lines[line - 1] + 1)
            if token.name == "(":
                end = self.source.find(")", self.offset)
                if end < 0:
                    raise token.error("unterminated Forth comment")
                self.offset = end + 1
            elif token.name == "\\":
                if "core-ext" not in self.wordsets:
                    raise token.error("Forth 2012 CORE EXT word '\\' requires 'bsv-use core-ext'")
                end = self.source.find("\n", self.offset)
                self.offset = len(self.source) if end < 0 else end + 1
            else:
                return token
        raise StopIteration


TOKEN = re.compile(r"'[ -~]'(?=\s|$)|\S+")
CONTROL = {":", ";", "if", "else", "then"}
RESERVED_STEPS = {"deploy", "split", "fused"}


@dataclass(frozen=True)
class Shuffle:
    name: str


@dataclass(frozen=True)
class Conditional:
    yes: tuple
    no: tuple


@dataclass(frozen=True)
class Located:
    instruction: object
    source: Token


@dataclass(frozen=True)
class Word:
    takes: tuple[str, ...]
    gives: tuple[str, ...]
    body: tuple
    location: str
    host_uses: tuple[Token, ...] = ()
    name: str | None = None
    ranges: tuple[RangeType, ...] = ()

    def slots(self, kinds):
        refinements = {item.name: item.slot for item in self.ranges}
        return tuple(refinements[kind] if kind in refinements else Slot.of(kind) for kind in kinds)


@dataclass(frozen=True)
class Work:
    name: str
    input: str
    word: Word
    owner: str


@dataclass(frozen=True)
class Recovery:
    height: int
    owner: str


@dataclass(frozen=True)
class Program:
    words: dict[str, Word]
    work: tuple[Work, Work]
    join: Word
    join_name: str
    operator: str
    independent: tuple[tuple[str, int], ...]
    optional_wordsets: tuple[str, ...]
    gate: Work | None = None
    recovery: Recovery | None = None

    @property
    def input_order(self):
        return tuple(step.input for step in self.work) + ((self.gate.input,) if self.gate else ())

    @property
    def shared_input(self):
        # Two workers and at most one gate can repeat at most one distinct input.
        order = self.input_order
        return next((name for name in order if order.count(name) > 1), None)


@dataclass(frozen=True)
class ParentOutput:
    step: str
    vout: int


@dataclass(frozen=True)
class Template:
    name: str
    inputs: tuple[ParentOutput, ...]
    authorizers: tuple[str, ...]
    outputs: tuple[str, ...]
    executes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    mode: str
    program: Program
    templates: tuple[Template, ...]
    fusion_blockers: tuple[str, ...]
    boundary_reasons: tuple[str, ...] = ()


def required(tokens, at, field):
    value = next(tokens, None)
    if value is None:
        raise at.error(f"expected {field} after {at.text!r}")
    return value


def identifier(tokens, at, field):
    token = required(tokens, at, field)
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", token.name):
        raise token.error(f"invalid {field} {token.text!r}")
    return token.name


def transform(stack, takes, gives, at):
    start = len(stack) - len(takes)
    if start < 0 or not all(value.within(target) for value, target in zip(stack[start:], takes, strict=True)):
        expected = tuple(slot.describe() for slot in takes)
        actual = tuple(slot.describe() for slot in stack)
        raise at.error(f"{at.text!r} expected stack suffix {expected}, found {actual}")
    stack[start:] = gives


def unavailable(token, *, enabled):
    name = token.name
    if name in CORE_EXT_WORDS and "core-ext" not in enabled:
        return token.error(f"Forth 2012 CORE EXT word {token.text!r} requires 'bsv-use core-ext'")
    if name in CORE_WORDS or name in CORE_EXT_WORDS:
        wordset = "CORE" if name in CORE_WORDS else "CORE EXT"
        return token.error(f"Forth 2012 {wordset} word {token.text!r} cannot compile to BSV Script")
    return token.error(f"unknown Forth word {token.text!r}")


def body(tokens, stack, words, opener, ranges):
    instructions = []
    host_uses = {}
    for token in tokens:
        name = token.name
        if name in {"else", "then", ";"}:
            return tuple(instructions), tuple(host_uses), token
        if name == "if":
            transform(stack, (Slot.of("cell"),), (), token)
            other = list(stack)
            yes, yes_host, stop = body(tokens, stack, words, token, ranges)
            no, no_host = (), ()
            if stop.name == "else":
                no, no_host, stop = body(tokens, other, words, token, ranges)
            if stop.name != "then" or [slot.kind for slot in stack] != [slot.kind for slot in other]:
                raise token.error("IF must end in THEN and leave equal stack types on both branches")
            stack[:] = [a.merge(b) for a, b in zip(stack, other, strict=True)]
            instructions.append(Located(Conditional(yes, no), token))
            host_uses.update(dict.fromkeys((*yes_host, *no_host)))
            continue
        if name in CORE_EXT_SCRIPT and "core-ext" not in tokens.wordsets and name not in words:
            raise unavailable(token, enabled=tokens.wordsets)
        if name in SHUFFLES and name not in words:
            count, order, _ = SHUFFLES[name]
            entries = stack[-count:]
            if len(entries) != count:
                raise token.error(f"stack underflow at {token.text}")
            stack[-count:] = [entries[i] for i in order]
            instructions.append(Located(Shuffle(name), token))
            continue
        instruction = resolve(tokens, token, words, ranges)
        if isinstance(instruction, Literal):
            stack.append(Slot.literal(instruction))
        elif isinstance(instruction, Word):
            transform(stack, instruction.slots(instruction.takes), instruction.slots(instruction.gives), token)
            host_uses.update(dict.fromkeys(instruction.host_uses))
        else:
            start = len(stack) - len(instruction.takes)
            args = stack[start:] if start >= 0 else ()
            takes = tuple(map(Slot.of, instruction.takes))
            transform(stack, takes, (), token)
            stack.extend(primitive_outputs(instruction, args))
            if instruction.location == "host":
                host_uses[token] = None
        instructions.append(Located(instruction, token))
    raise opener.error(f"unterminated {opener.text!r}")


def resolve(tokens, token, words, ranges):
    name = token.name
    instruction = words.get(name) or NAMED_LITERALS.get(name) or PRIMITIVES.get(name) or HOST_WORDS.get(name)
    if instruction is not None:
        return instruction
    if name == "bytes-hex":
        value = required(tokens, token, "hexadecimal byte string")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value.text):
            raise value.error("BYTES-HEX requires whole bytes written as hexadecimal pairs")
        return Literal("bytes", bytes.fromhex(value.text))
    if name == "check-range":
        target = required(tokens, token, "declared range name")
        if target.name not in ranges:
            raise target.error(f"undefined range {target.text!r}")
        return ranges[target.name].check()
    try:
        literal = cell_literal(token.text)
    except ValueError as error:
        raise token.error(str(error)) from error
    if literal is not None:
        return literal
    if name in BSV_SOURCE:
        raise token.error(f"{token.text!r} is a source declaration and cannot be used inside a definition")
    raise unavailable(token, enabled=tokens.wordsets)


def require_script(word):
    if word.location != "script":
        uses = ", ".join(f"{token.text} (line {token.line}, column {token.column})"
                         for token in dict.fromkeys(word.host_uses))
        suffix = f": {uses}" if uses else ""
        raise CompileError(f"host-only words cannot compile to BSV Script{suffix}")


def check_word(words, at, takes, gives):
    word = words.get(at.name)
    if word is None:
        raise at.error(f"undefined worker or join word {at.text!r}")
    try:
        require_script(word)
    except CompileError as error:
        raise at.error(str(error)) from error
    if (word.takes, word.gives) != (takes, gives):
        raise at.error(f"{at.text!r} requires signature {takes} -- {gives}")
    return word


class SourceCompiler:
    def __init__(self, source):
        self.tokens = Tokens(source)
        self.words = {}
        self.ranges = {}
        self.effects = {}
        self.work = {}
        self.gate = None
        self.join = None
        self.operator = None
        self.recovery = None
        self.independent = []
        for token in self.tokens:
            try:
                self.declaration(token)
            except RecursionError as error:
                raise token.error("conditional nesting exceeds the compiler's recursion limit") from error
        if self.effects:
            at, _, _ = next(iter(self.effects.values()))
            raise at.error(f"stack effect for {at.text!r} has no following definition")

    @property
    def optional_wordsets(self):
        return tuple(sorted(self.tokens.wordsets))

    def effect(self, at):
        name = required(self.tokens, at, "definition name")
        if name.name in self.effects or name.name in CONTROL | BSV_SOURCE:
            raise name.error(f"invalid or duplicate effect declaration for {name.text!r}")
        before, after = [], []
        current = before
        for token in self.tokens:
            if token.name == ";" and current is after:
                self.effects[name.name] = name, tuple(before), tuple(after)
                return
            if token.name == "--" and current is before:
                current = after
            elif token.name in TYPES or token.name in self.ranges:
                current.append(token.name)
            else:
                raise token.error("expected a stack type, '--', or the closing ';'")
        raise at.error("unterminated BSV-EFFECT: declaration")

    def declare_range(self, at):
        name = identifier(self.tokens, at, "range name")
        if name in TYPES or name in self.ranges:
            raise at.error(f"duplicate or reserved range name {name!r}")
        base = required(self.tokens, at, "numeric base type")
        if base.name not in NUMERIC_TYPES:
            raise base.error("range base must be cell, u32, route, or script-int")
        endpoints = []
        for label in ("inclusive lower bound", "exclusive upper bound"):
            token = required(self.tokens, at, label)
            try:
                endpoints.append(range_bound(token.text))
            except ValueError as error:
                raise token.error(str(error)) from error
        end = required(self.tokens, at, "';'")
        if end.name != ";" or endpoints[0] >= endpoints[1]:
            raise at.error("RANGE: requires a nonempty interval followed by ';'")
        spec = RangeType(name, base.name, *endpoints)
        if not spec.slot.within(Slot.of(base.name)):
            raise base.error(f"range {name!r} exceeds the value range of {base.name}")
        self.ranges[name] = spec

    def define(self, at):
        name = required(self.tokens, at, "definition name")
        declaration = self.effects.pop(name.name, None)
        if declaration is None:
            raise name.error(f"typed Script builds require a preceding 'bsv-effect: {name.text} ... ;'")
        _, takes, gives = declaration
        ranges = tuple(self.ranges[kind] for kind in dict.fromkeys((*takes, *gives)) if kind in self.ranges)
        signature = Word(takes, gives, (), "script", ranges=ranges)
        stack = list(signature.slots(takes))
        instructions, host_uses, stop = body(self.tokens, stack, self.words, at, self.ranges)
        if stop.name != ";":
            raise stop.error(f"unexpected {stop.text!r}, expected ';'")
        outputs = signature.slots(gives)
        if len(stack) != len(outputs) or not all(value.within(target) for value, target in zip(stack, outputs, strict=True)):
            actual = tuple(slot.describe() for slot in stack)
            expected = tuple(slot.describe() for slot in outputs)
            raise name.error(f"body leaves {actual}, declared {gives} with ranges {expected}")
        self.words[name.name] = Word(takes, gives, instructions, "host" if host_uses else "script",
                                     host_uses, name.name, ranges)

    def declaration(self, token):
        tokens = self.tokens
        match token.name:
            case "bsv-use":
                wordset = required(tokens, token, "optional word set")
                if wordset.name not in OPTIONAL_WORDSETS:
                    raise wordset.error(f"optional Forth word set {wordset.text!r} is unavailable")
                tokens.wordsets.add(wordset.name)
            case "bsv-effect:":
                self.effect(token)
            case "range:":
                self.declare_range(token)
            case ":":
                self.define(token)
            case "work:":
                name = identifier(tokens, token, "work step")
                if name in self.work or name in RESERVED_STEPS:
                    raise token.error(f"invalid or duplicate work step {name!r}")
                input_name = identifier(tokens, token, "input name")
                word = check_word(self.words, required(tokens, token, "worker word"), ("u32",), ("u32",))
                owner = identifier(tokens, token, "signer role")
                self.work[name] = Work(name, input_name, word, owner)
            case "gate:":
                if self.gate is not None:
                    raise token.error("expected at most one gate")
                name = identifier(tokens, token, "gate step")
                input_name = identifier(tokens, token, "input name")
                word = check_word(self.words, required(tokens, token, "gate word"), ("u32",), ("cell",))
                owner = identifier(tokens, token, "signer role")
                self.gate = Work(name, input_name, word, owner)
            case "join:":
                if self.join is not None:
                    raise token.error("expected one join")
                name = identifier(tokens, token, "join step")
                left = identifier(tokens, token, "first work step")
                right = identifier(tokens, token, "second work step")
                word = check_word(self.words, required(tokens, token, "join word"), ("u32", "u32"), ("route",))
                self.join = token, name, left, right, word
            case "split-authority:":
                if self.operator is not None:
                    raise token.error("expected one split authority")
                self.operator = identifier(tokens, token, "signer role")
            case "recovery:":
                if self.recovery is not None:
                    raise token.error("expected at most one recovery policy")
                height = required(tokens, token, "decimal block height")
                if not re.fullmatch(r"[0-9]{1,9}", height.text) or not 0 < int(height.text) < LOCKTIME_THRESHOLD:
                    raise height.error("recovery height must be a block height from 1 to 499999999")
                self.recovery = Recovery(int(height.text), identifier(tokens, token, "recovery signer role"))
            case "independent-submit":
                self.independent.append((identifier(tokens, token, "gate or work step"), token.line))
            case name if name in self.work or self.gate is not None and name == self.gate.name:
                # The original prototype spelled this declaration "<step> independent-submit".
                directive = required(tokens, token, "independent-submit")
                if directive.name != "independent-submit":
                    raise directive.error("expected independent-submit after the work step")
                self.independent.append((name, token.line))
            case name if name in CORE_EXT_SCRIPT and "core-ext" not in tokens.wordsets and name not in self.words:
                raise unavailable(token, enabled=tokens.wordsets)
            case name if name in self.words or name in PRIMITIVES or name in SHUFFLES or name in HOST_WORDS \
                    or name in NAMED_LITERALS:
                raise token.error("top-level execution is unavailable in a Script build")
            case _:
                raise unavailable(token, enabled=tokens.wordsets)

    def program(self):
        if len(self.work) != 2 or self.join is None or self.operator is None:
            raise CompileError("expected two work declarations, one join and one split authority")
        at, name, left, right, word = self.join
        if left == right or set((left, right)) != self.work.keys() or name in self.work or name in RESERVED_STEPS:
            raise at.error("join must consume both work steps once and have a distinct step name")
        step_names = set(self.work)
        if self.gate is not None:
            if self.gate.name in step_names | RESERVED_STEPS | {name}:
                raise CompileError(f"invalid or duplicate gate step {self.gate.name!r}")
            step_names.add(self.gate.name)
        for step, line in self.independent:
            if step not in step_names:
                raise CompileError(f"line {line}: unknown gate or work step {step!r}")
        return Program(self.words, (self.work[left], self.work[right]), word, name, self.operator,
                       tuple(self.independent), self.optional_wordsets, self.gate, self.recovery)


def parse(source):
    return SourceCompiler(source).program()


def availability(program, data, authorizers):
    stages = (*program.work, program.gate) if program.gate is not None else program.work
    if data is None:
        data = program.input_order
    if authorizers is None:
        authorizers = (program.operator, *(step.owner for step in stages))
    return frozenset(data), frozenset(authorizers)


def fusion_constraints(program, data, authorizers):
    blockers = [
        {"code": "independent_submit", "step": step, "line": line,
         "message": f"line {line}: independent-submit {step} requires a separate transaction for {step}"}
        for step, line in program.independent
    ]
    stages = (*program.work, program.gate) if program.gate is not None else program.work
    for work in stages:
        if work.input not in data:
            blockers.append({"code": "unavailable_input", "step": work.name, "input": work.input,
                             "message": f"{work.name}: input {work.input} is unavailable at fusion"})
        if work.owner not in authorizers:
            blockers.append({"code": "unavailable_authorizer", "step": work.name, "authorizer": work.owner,
                             "message": f"{work.name}: authorizer {work.owner} is unavailable at fusion"})
    return blockers


def fused_template(program):
    a, b = program.work
    gate = program.gate
    owners = (a.owner, b.owner, gate.owner) if gate is not None else (a.owner, b.owner)
    order = (gate.name, a.name, b.name) if gate is not None else (a.name, b.name)
    return Template("fused", (ParentOutput("deploy", 0),), owners, ("terminal",), (*order, program.join_name))


def gate_constraints(program, data, authorizers):
    gate = program.gate
    if gate is None:
        return []
    reasons = [
        {"code": "independent_submit", "step": step, "line": line,
         "message": f"line {line}: independent-submit requires its own transaction for {step}"}
        for step, line in program.independent if step == gate.name
    ]
    if gate.owner != program.operator:
        reasons.append({"code": "different_authorities", "step": gate.name,
                        "message": f"{gate.name}: gate and split have different authorities"})
    if gate.input not in data:
        reasons.append({"code": "unavailable_input", "step": gate.name, "input": gate.input,
                        "message": f"{gate.name}: input {gate.input} is unavailable at split"})
    if gate.owner not in authorizers:
        reasons.append({"code": "unavailable_authorizer", "step": gate.name, "authorizer": gate.owner,
                        "message": f"{gate.name}: authorizer {gate.owner} is unavailable at split"})
    return reasons


def split_templates(program, separate_gate):
    a, b = program.work
    gate = program.gate
    prefix, fork_parent, fork_steps = (), "deploy", ("split",)
    if separate_gate:
        prefix = (Template(gate.name, (ParentOutput("deploy", 0),), (gate.owner,), ("split-lock",), (gate.name,)),)
        fork_parent = gate.name
    elif gate is not None:
        fork_steps = (gate.name, "split")
    return (
        *prefix,
        Template("split", (ParentOutput(fork_parent, 0),), (program.operator,), ("work", "work"), fork_steps),
        Template(a.name, (ParentOutput("split", 0),), (a.owner,), ("result", "data"), (a.name,)),
        Template(b.name, (ParentOutput("split", 1),), (b.owner,), ("result", "data"), (b.name,)),
        Template(program.join_name, (ParentOutput(a.name, 0), ParentOutput(b.name, 0)), (), ("terminal",),
                 (program.join_name,)),
    )


def schedule(program, mode="auto", *, available_data=None, available_authorizers=None, gate_boundary="auto"):
    if mode not in {"auto", "fused", "split"}:
        raise CompileError(f"unknown schedule {mode!r}")
    gate = program.gate
    if gate_boundary not in GATE_BOUNDARIES:
        raise CompileError(f"unknown gate boundary {gate_boundary!r}")
    if gate_boundary != "auto" and (gate is None or mode == "fused"):
        raise CompileError("an explicit gate boundary requires a gated split schedule")
    data, authorizers = availability(program, available_data, available_authorizers)
    blockers = [row["message"] for row in fusion_constraints(program, data, authorizers)]
    if mode == "fused" and blockers:
        raise CompileError("fusion excluded: " + "; ".join(blockers))
    if mode == "auto":
        mode = "split" if blockers or gate_boundary != "auto" else "fused"
    reasons = []
    if mode == "fused":
        templates = (fused_template(program),)
    else:
        separate = False
        if gate is not None:
            reasons = [row["message"] for row in gate_constraints(program, data, authorizers)]
            if gate_boundary == "merged" and reasons:
                raise CompileError("merged gate excluded: " + "; ".join(reasons))
            separate = bool(reasons) or gate_boundary == "separate"
            if separate:
                if not reasons:
                    reasons.append(f"{gate.name}: selected a separate gate transaction")
            else:
                reasons.append(f"{gate.name}: guard and split are executed together under {program.operator}")
        shared = program.shared_input
        if shared is not None:
            first = gate.name if separate and gate.input == shared else "split"
            reasons.append(f"{first}: input {shared} must be available here to bind it for all consuming steps")
        templates = split_templates(program, separate)
    return Plan(mode, program, templates, tuple(blockers), tuple(reasons))


def evaluate(word, *values, context=None):
    if len(values) != len(word.takes):
        raise ValueError("incorrect argument count for Forth word")
    for kind, slot, value in zip(word.takes, word.slots(word.takes), values, strict=True):
        bounds = slot.bounds
        if slot.kind in NUMERIC_TYPES and (type(value) is not int or
                                          bounds is not None and not bounds[0] <= value <= bounds[1]):
            raise ValueError(f"argument is out of range for {kind}")
        if kind == "bytes" and not isinstance(value, bytes):
            raise ValueError("expected a bytes argument")
    stack = list(values)
    frames = [expanded(word.body)]
    while frames:
        entry = next(frames[-1], None)
        if entry is None:
            frames.pop()
            continue
        instruction, _ = entry
        if isinstance(instruction, Literal):
            stack.append(instruction.value)
        elif isinstance(instruction, Conditional):
            frames.append(expanded(instruction.yes if stack.pop() else instruction.no))
        elif isinstance(instruction, Shuffle):
            count, order, _ = SHUFFLES[instruction.name]
            entries = stack[-count:]
            stack[-count:] = [entries[i] for i in order]
        else:
            start = len(stack) - len(instruction.takes)
            args = stack[start:]
            if instruction.location == "host":
                args = [context, *args]
            stack[start:] = instruction.run(*args)
    return tuple(stack)


def expanded(instructions):
    frames = [iter(instructions)]
    while frames:
        entry = next(frames[-1], None)
        if entry is None:
            frames.pop()
            continue
        if isinstance(entry, Located):
            instruction, source = entry.instruction, entry.source
        else:
            instruction, source = entry, None
        if isinstance(instruction, Word):
            frames.append(iter(instruction.body))
        else:
            yield instruction, source


def lower(word, *, check_input_ranges=True):
    require_script(word)
    try:
        prefix = entry_range_checks(word) if check_input_ranges else b""
        return prefix + lower_body(word.body)
    except RecursionError as error:
        raise CompileError("expanded conditional nesting exceeds the compiler's recursion limit") from error


def entry_range_checks(word):
    refinements = {item.name: item for item in word.ranges}
    code = bytearray()
    for depth, kind in enumerate(reversed(word.takes)):
        if kind not in refinements:
            continue
        if depth:
            code.extend(asm("OP_OVER") if depth == 1 else number(depth) + asm("OP_PICK"))
        code.extend(refinements[kind].check().code)
        if depth:
            code.extend(asm("OP_DROP"))
    return bytes(code)


def lower_body(instructions):
    folded = []
    for instruction, _ in expanded(instructions):
        if isinstance(instruction, Primitive) and not instruction.may_fail:
            count = len(instruction.takes)
            args = folded[-count:]
            if len(args) == count and all(isinstance(arg, Literal) for arg in args):
                values = instruction.run(*(arg.value for arg in args))
                folded[-count:] = [Literal(kind, value) for kind, value in zip(instruction.gives, values, strict=True)]
                continue
        folded.append(instruction)

    code = bytearray()
    for index, instruction in enumerate(folded):
        if isinstance(instruction, Literal):
            if (instruction == Literal("u32", 1) and index + 1 < len(folded)
                    and folded[index + 1] is PRIMITIVES["u32+"]):
                continue
            code.extend(instruction.lower())
        elif isinstance(instruction, Shuffle):
            code.extend(asm(SHUFFLES[instruction.name][2]))
        elif isinstance(instruction, Conditional):
            code.extend(asm("OP_0NOTEQUAL OP_IF") + lower_body(instruction.yes) + asm("OP_ELSE")
                        + lower_body(instruction.no) + asm("OP_ENDIF"))
        elif instruction is PRIMITIVES["u32+"] and index and folded[index - 1] == Literal("u32", 1):
            code.extend(asm("OP_1ADD") + WRAP_U32)
        else:
            code.extend(instruction.code)
    return bytes(code)

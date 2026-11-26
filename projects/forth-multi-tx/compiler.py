"""Typed Forth front end, followed by transaction scheduling and Script lowering."""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
import re

from shared.script import asm, number, push

U32 = 1 << 32
TYPES = {"u32", "bool", "route", "bytes", "script", "transaction", "outpoint", "utxo", "request"}


def push_value(value):
    if len(value) == 1 and 1 <= value[0] <= 16:
        return number(value[0])
    if value == b"\x81":
        return number(-1)
    return push(value)


@dataclass(frozen=True)
class Literal:
    kind: str
    value: int | bytes

    def lower(self):
        if isinstance(self.value, bytes):
            return push_value(self.value)
        return number(self.value)


@dataclass(frozen=True)
class Primitive:
    takes: tuple[str, ...]
    gives: tuple[str, ...]
    code: bytes | None
    run: Callable[..., tuple]
    evidence: str

    @property
    def location(self):
        return "host" if self.code is None else "script"


def chain(takes, gives, code, run):
    return Primitive(tuple(takes.split()), tuple(gives.split()), code, run, "script execution")


WRAP_U32 = number(U32) + asm("OP_MOD")
PRIMITIVES = {
    "u32+": chain("u32 u32", "u32", asm("OP_ADD") + WRAP_U32, lambda x, y: ((x + y) % U32,)),
    "u32<": chain("u32 u32", "bool", asm("OP_LESSTHAN"), lambda x, y: (int(x < y),)),
    "cat": chain("bytes bytes", "bytes", asm("OP_CAT"), lambda x, y: (x + y,)),
    "sha256": chain("bytes", "bytes", asm("OP_SHA256"), lambda x: (sha256(x).digest(),)),
    "bytes=": chain("bytes bytes", "bool", asm("OP_EQUAL"), lambda x, y: (int(x == y),)),
}


def host(takes, gives, method, evidence):
    return Primitive(tuple(takes.split()), tuple(gives.split()), None,
                     lambda context, value: (getattr(context, method)(value),), evidence)


HOST_WORDS = {
    "lookup-utxo": host("outpoint", "utxo", "lookup", "live UTXO provider"),
    "sign": host("request", "bytes", "sign", "external signer and native CHECKSIG"),
    "submit": host("transaction", "bytes", "submit", "node transaction admission"),
    "utxo-outpoint": host("utxo", "outpoint", "outpoint", "bound parent transaction bytes"),
    "utxo-script": host("utxo", "script", "script", "bound output script"),
}
ROUTES = {"review": Literal("route", 0), "settle": Literal("route", 1)}
SHUFFLES = {
    "dup": (1, (0, 0), "OP_DUP"),
    "drop": (1, (), "OP_DROP"),
    "swap": (2, (1, 0), "OP_SWAP"),
    "over": (2, (0, 1, 0), "OP_OVER"),
}


@dataclass(frozen=True)
class Shuffle:
    name: str


@dataclass(frozen=True)
class Conditional:
    yes: tuple
    no: tuple


@dataclass(frozen=True)
class Word:
    takes: tuple[str, ...]
    gives: tuple[str, ...]
    body: tuple
    location: str


@dataclass(frozen=True)
class Work:
    name: str
    input: str
    word: Word
    owner: str


@dataclass(frozen=True)
class Program:
    words: dict[str, Word]
    work: tuple[Work, Work]
    join: Word
    join_name: str
    operator: str
    independent: tuple[tuple[str, int], ...]


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


@dataclass(frozen=True)
class Plan:
    mode: str
    program: Program
    templates: tuple[Template, ...]
    fusion_blockers: tuple[str, ...]


class CompileError(ValueError):
    pass


def transform(stack, takes, gives):
    start = len(stack) - len(takes)
    if start < 0 or tuple(stack[start:]) != takes:
        raise CompileError(f"expected stack suffix {takes}, found {tuple(stack)}")
    stack[start:] = gives


def body(tokens, stack, words):
    instructions = []
    location = "script"
    for token in tokens:
        if token in {"else", "then"}:
            return tuple(instructions), location, token
        if token == "if":
            transform(stack, ("bool",), ())
            other = list(stack)
            yes, yes_location, stop = body(tokens, stack, words)
            if stop != "else":
                raise CompileError("if requires else and then")
            no, no_location, stop = body(tokens, other, words)
            if stop != "then" or stack != other:
                raise CompileError("if requires then and equal branch stack types")
            instructions.append(Conditional(yes, no))
            if "host" in (yes_location, no_location):
                location = "host"
            continue
        if token in SHUFFLES:
            count, order, _ = SHUFFLES[token]
            types = stack[-count:]
            if len(types) != count:
                raise CompileError(f"stack underflow at {token}")
            stack[-count:] = [types[i] for i in order]
            instructions.append(Shuffle(token))
            continue
        if token in ROUTES:
            instruction = ROUTES[token]
        elif re.fullmatch(r"[0-9]+", token):
            value = int(token)
            if value >= U32:
                raise CompileError("u32 literal out of range")
            instruction = Literal("u32", value)
        elif re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", token):
            instruction = Literal("bytes", bytes.fromhex(token[2:]))
        else:
            instruction = words.get(token) or PRIMITIVES.get(token) or HOST_WORDS.get(token)
        if isinstance(instruction, Literal):
            stack.append(instruction.kind)
        elif instruction is not None:
            transform(stack, instruction.takes, instruction.gives)
            if instruction.location == "host":
                location = "host"
        else:
            raise CompileError(f"unknown Forth word {token!r}")
        instructions.append(instruction)
    return tuple(instructions), location, None


def name_ok(name):
    return re.fullmatch(r"[a-z][a-z0-9_-]*", name) is not None


def parse(source):
    words = {}
    work = {}
    independent = []
    join = None
    operator = None
    for line_no, line in enumerate(source.splitlines(), 1):
        line = line.partition("\\")[0].strip()
        if not line:
            continue
        try:
            if line.startswith(":"):
                match = re.fullmatch(r":\s+(\S+)\s+\(([^()]*)--([^()]*)\)\s+(.*?)\s*;", line)
                if not match:
                    raise CompileError("expected : name ( inputs -- outputs ) words ;")
                name, before, after, code = match.groups()
                if not name_ok(name) or name in words or name in PRIMITIVES or name in HOST_WORDS \
                        or name in SHUFFLES or name in ROUTES or name in {"if", "else", "then"}:
                    raise CompileError(f"invalid or duplicate word {name!r}")
                takes, gives = tuple(before.split()), tuple(after.split())
                if (set(takes) | set(gives)) - TYPES:
                    raise CompileError("unknown stack type")
                stack = list(takes)
                instructions, location, stop = body(iter(code.split()), stack, words)
                if stop or tuple(stack) != gives:
                    raise CompileError(f"body leaves {tuple(stack)}, declared {gives}")
                words[name] = Word(takes, gives, instructions, location)
                continue
            tokens = line.split()
            match tokens:
                case [input_name, word_name, owner, "work:", step] if all(map(name_ok, (input_name, owner, step))):
                    if step in work or step in {"deploy", "split", "fused"}:
                        raise CompileError(f"invalid or duplicate work step {step!r}")
                    word = words.get(word_name)
                    check_word(word, ("u32",), ("u32",), word_name)
                    work[step] = Work(step, input_name, word, owner)
                case [left, right, word_name, "join:", name] if name_ok(name) and join is None:
                    word = words.get(word_name)
                    check_word(word, ("u32", "u32"), ("route",), word_name)
                    join = left, right, word, name
                case [owner, "split-authority"] if name_ok(owner) and operator is None:
                    operator = owner
                case [step, "independent-submit"]:
                    independent.append((step, line_no))
                case _:
                    raise CompileError("invalid declaration")
        except CompileError as error:
            raise CompileError(f"line {line_no}: {error}") from error
    if len(work) != 2 or join is None or operator is None:
        raise CompileError("expected two work declarations, one join and one split authority")
    left, right, word, name = join
    if left == right or set((left, right)) != work.keys() or name in work or name in {"deploy", "split", "fused"}:
        raise CompileError("join must consume both work steps once and have a distinct step name")
    for step, line_no in independent:
        if step not in work:
            raise CompileError(f"line {line_no}: unknown work step {step!r}")
    return Program(words, (work[left], work[right]), word, name, operator, tuple(independent))


def check_word(word, takes, gives, name):
    if word is None or (word.takes, word.gives, word.location) != (takes, gives, "script"):
        raise CompileError(f"{name!r} must be a Script word with signature {takes} -- {gives}")


def schedule(program, mode="auto", *, available_data=None, available_authorizers=None):
    if mode not in {"auto", "fused", "split"}:
        raise CompileError(f"unknown schedule {mode!r}")
    a, b = program.work
    data = {a.input, b.input} if available_data is None else set(available_data)
    authorizers = {a.owner, b.owner} if available_authorizers is None else set(available_authorizers)
    blockers = [f"line {line}: {step} independent-submit requires a separate transaction for {step}"
                for step, line in program.independent]
    for work in program.work:
        if work.input not in data:
            blockers.append(f"{work.name}: input {work.input} is unavailable at fusion")
        if work.owner not in authorizers:
            blockers.append(f"{work.name}: authorizer {work.owner} is unavailable at fusion")
    if mode == "fused" and blockers:
        raise CompileError("fusion excluded: " + "; ".join(blockers))
    if mode == "auto":
        mode = "split" if blockers else "fused"
    if mode == "fused":
        templates = (Template("fused", (ParentOutput("deploy", 0),), (a.owner, b.owner), ("terminal",)),)
    else:
        templates = (
            Template("split", (ParentOutput("deploy", 0),), (program.operator,), ("work", "work")),
            Template(a.name, (ParentOutput("split", 0),), (a.owner,), ("result", "data")),
            Template(b.name, (ParentOutput("split", 1),), (b.owner,), ("result", "data")),
            Template(program.join_name, (ParentOutput(a.name, 0), ParentOutput(b.name, 0)), (), ("terminal",)),
        )
    return Plan(mode, program, templates, tuple(blockers))


def evaluate(word, *values, context=None):
    stack = list(values)

    def run(instructions):
        for instruction in instructions:
            if isinstance(instruction, Word):
                run(instruction.body)
            elif isinstance(instruction, Literal):
                stack.append(instruction.value)
            elif isinstance(instruction, Conditional):
                run(instruction.yes if stack.pop() else instruction.no)
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

    if len(values) != len(word.takes):
        raise ValueError("incorrect argument count for Forth word")
    run(word.body)
    return tuple(stack)


def inline(instructions):
    for instruction in instructions:
        if isinstance(instruction, Word):
            yield from inline(instruction.body)
        else:
            yield instruction


def lower(word):
    if word.location != "script":
        raise CompileError("host word cannot lower to Script")
    return lower_body(word.body)


def lower_body(instructions):
    folded = []
    for instruction in inline(instructions):
        if isinstance(instruction, Primitive):
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
            code.extend(asm("OP_IF") + lower_body(instruction.yes) + asm("OP_ELSE")
                        + lower_body(instruction.no) + asm("OP_ENDIF"))
        elif instruction is PRIMITIVES["u32+"] and index and folded[index - 1] == Literal("u32", 1):
            code.extend(asm("OP_1ADD") + WRAP_U32)
        else:
            code.extend(instruction.code)
    return bytes(code)

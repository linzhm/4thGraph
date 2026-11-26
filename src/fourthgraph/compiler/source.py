"""Forth 2012 Core subset, typed BSV declarations and transaction scheduling."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import InitVar, dataclass, field
from hashlib import sha256
from os.path import relpath
from pathlib import Path
import re

from fourthgraph import PROJECT_VERSION
from fourthgraph.bsv.script import asm, number

from fourthgraph.compiler.ranges import NUMERIC_TYPES, RangeType, Slot, primitive_outputs, range_bound
from fourthgraph.stdlib import (
    WALLET_BACKEND, LibraryImport, interface_digest, p256_vocabulary, read_library, required_source,
)
from fourthgraph.workflow.transaction_graph import CompileError, ParentOutput, Port, StageGraph, StageNode, Template, TransactionGraph
from fourthgraph.compiler.wordsets import (
    BSV_SOURCE, CORE_EXT_WORDS, CORE_WORDS, FILE_EXT_SOURCE, FILE_EXT_WORDS, HOST_WORDS,
    LEGACY_IMPLICIT_END, NAMED_LITERALS, NATIVE_OPCODES, OPTIONAL_WORDSETS, PRIMITIVES, SHUFFLES, TYPES, WRAP_U32,
    Literal, Primitive, cell_literal,
)

PROJECT_NAME = "4thGraph"
PROJECT_DESCRIPTION = "A Forth compiler for BSV Script and multi-transaction workflows."
GATE_BOUNDARIES = ("auto", "merged", "separate")
LOCKTIME_THRESHOLD = 500_000_000
MAX_EXPANSION = 16_384


@dataclass(frozen=True)
class Token:
    text: str
    line: int
    column: int
    module: str | None = None

    @property
    def name(self):
        return self.text.casefold()

    @property
    def location(self):
        prefix = f"{self.module}, " if self.module else ""
        return f"{prefix}line {self.line}, column {self.column}"

    def error(self, message):
        return CompileError(f"{self.location}: {message}")


class Tokens:
    def __init__(self, source, module=None):
        self.source = source.replace("\r\n", "\n").replace("\r", "\n")
        self.module = module
        self.offset = 0
        self.pending = None
        self.lines = [0, *(match.end() for match in re.finditer("\n", self.source))]

    def __iter__(self):
        return self

    def __next__(self):
        if self.pending is not None:
            token, self.pending = self.pending, None
            return token
        while match := TOKEN.search(self.source, self.offset):
            self.offset = match.end()
            line = bisect_right(self.lines, match.start())
            token = Token(match[0], line, match.start() - self.lines[line - 1] + 1, self.module)
            if token.name == "(":
                end = self.source.find(")", self.offset)
                if end < 0:
                    raise token.error("unterminated Forth comment")
                self.offset = end + 1
            elif token.name == "\\":
                end = self.source.find("\n", self.offset)
                self.offset = len(self.source) if end < 0 else end + 1
            else:
                return token
        raise StopIteration

    def filename(self, at):
        end = self.source.find("\n", self.offset)
        end = len(self.source) if end < 0 else end
        name = re.match(r"\s*(\S+)", self.source[self.offset:end])
        if name is None:
            raise at.error(f"expected a filename after {at.text!r}")
        self.offset += name.end()
        return name[1]

    def stack_effect(self, *, require_separator=True):
        opening = re.match(r"\s*\((?=\s)", self.source[self.offset:])
        if opening is None:
            return None
        start = self.offset + opening.end()
        end = self.source.find(")", start)
        if end < 0:
            return None
        terms = self.source[start:end].casefold().split()
        if require_separator and "--" not in terms:
            return None
        self.offset = end + 1
        return terms

    def peek(self):
        self.pending = next(self, None)
        return self.pending


TOKEN = re.compile(r"'[ -~]'(?=\s|$)|\S+")
CONTROL = {":", ";", "if", "else", "then"}
BUILTIN_WORDS = (CONTROL | BSV_SOURCE | FILE_EXT_SOURCE | PRIMITIVES.keys() | SHUFFLES.keys()
                 | NAMED_LITERALS.keys() | HOST_WORDS.keys() | {"bytes-hex", "check-range"})
RESERVED_STEPS = {"deploy", "split", "fused"}


@dataclass(frozen=True)
class Shuffle:
    name: str


@dataclass(frozen=True)
class NamedInput:
    index: int


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
    lock: LockBlock | None = None

    def slots(self, kinds):
        refinements = {item.name: item.slot for item in self.ranges}
        return tuple(refinements[kind] if kind in refinements else Slot.of(kind) for kind in kinds)


@dataclass(frozen=True)
class Work:
    name: str
    input: str
    word: Word
    owner: str
    declaration: Token
    input_token: Token


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
    join_declaration: Token
    join_inputs: tuple[Token, Token]
    gate: Work | None = None
    recovery: Recovery | None = None
    libraries: tuple[LibraryImport, ...] = ()

    @property
    def input_order(self):
        return tuple(step.input for step in self.work) + ((self.gate.input,) if self.gate else ())

    @property
    def shared_input(self):
        # Two workers and at most one gate can repeat at most one distinct input.
        order = self.input_order
        return next((name for name in order if order.count(name) > 1), None)

    def stage_graph(self):
        inputs, stages = {}, []
        gate_output = None
        if self.gate is not None:
            gate = self.gate
            source = Port(gate.input, "u32", gate.input_token)
            inputs[source.name] = source
            gate_output = Port(f"{gate.name}:accepted", "guard", gate.declaration)
            stages.append(StageNode(gate.name, gate.word.name, gate.owner, (source,), (gate_output,), gate.declaration))
        for step in self.work:
            source = Port(step.input, "u32", step.input_token)
            inputs.setdefault(source.name, source)
            result = Port(f"{step.name}:result", "u32", step.declaration, linear=True)
            guard = () if gate_output is None else (Port(gate_output.name, "guard", step.declaration),)
            stages.append(StageNode(step.name, step.word.name, step.owner, (source, *guard), (result,), step.declaration))
        takes = tuple(Port(f"{token.name}:result", "u32", token) for token in self.join_inputs)
        result = Port(f"{self.join_name}:route", "route", self.join_declaration)
        stages.append(StageNode(self.join_name, self.join.name, None, takes, (result,), self.join_declaration))
        return StageGraph.build(tuple(inputs.values()), stages)


@dataclass(frozen=True)
class Stage:
    name: str
    word: Word
    source: Token
    result: Token
    owner: str
    declaration: Token


@dataclass(frozen=True)
class Workflow:
    input: Token
    stages: tuple[Stage, ...]
    independent: tuple[tuple[str, int], ...] = ()
    recovery: Recovery | None = None
    libraries: tuple[LibraryImport, ...] = ()

    def stage_graph(self):
        source = Port(self.input.name, "u32", self.input, linear=True)
        return StageGraph.build((source,), [
            StageNode(stage.name, stage.word.name, stage.owner,
                      (Port(stage.source.name, stage.word.takes[0], stage.source),),
                      (Port(stage.result.name, stage.word.gives[0], stage.result, linear=True),), stage.declaration)
            for stage in self.stages
        ])


@dataclass(frozen=True)
class Plan:
    mode: str
    program: Program | Workflow
    templates: tuple[Template, ...]
    fusion_blockers: tuple[str, ...]
    boundary_reasons: tuple[str, ...] = ()
    deployment_outputs: tuple[str, ...] = ("root-lock",)
    stage_graph: InitVar[StageGraph | None] = None
    graph: TransactionGraph = field(init=False)

    def __post_init__(self, stage_graph):
        graph = TransactionGraph(stage_graph or self.program.stage_graph(), self.deployment_outputs, self.templates)
        object.__setattr__(self, "graph", graph)


def required(tokens, at, field):
    value = next(tokens, None)
    if value is None:
        raise at.error(f"expected {field} after {at.text!r}")
    return value


def named_token(tokens, at, field):
    token = required(tokens, at, field)
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", token.name):
        raise token.error(f"invalid {field} {token.text!r}")
    return token


def identifier(tokens, at, field):
    return named_token(tokens, at, field).name


def transform(stack, takes, gives, at):
    start = len(stack) - len(takes)
    if start < 0 or not all(value.within(target) for value, target in zip(stack[start:], takes, strict=True)):
        expected = tuple(slot.describe() for slot in takes)
        actual = tuple(slot.describe() for slot in stack)
        raise at.error(f"{at.text!r} expected stack suffix {expected}, found {actual}")
    stack[start:] = gives


def unavailable(token):
    for wordset, words in (("CORE", CORE_WORDS), ("CORE EXT", CORE_EXT_WORDS), ("FILE EXT", FILE_EXT_WORDS)):
        if token.name in words:
            return token.error(f"Forth 2012 {wordset} word {token.text!r} cannot compile to BSV Script")
    return token.error(f"unknown Forth word {token.text!r}")


def body(tokens, stack, words, opener, ranges, *, native_opcodes=False):
    instructions = []
    host_uses = {}
    for token in tokens:
        name = token.name
        if name in {"else", "then", ";"}:
            return tuple(instructions), tuple(host_uses), token
        if name == "if":
            transform(stack, (Slot.of("cell"),), (), token)
            other = list(stack)
            yes, yes_host, stop = body(tokens, stack, words, token, ranges, native_opcodes=native_opcodes)
            no, no_host = (), ()
            if stop.name == "else":
                no, no_host, stop = body(tokens, other, words, token, ranges, native_opcodes=native_opcodes)
            if stop.name != "then" or [slot.kind for slot in stack] != [slot.kind for slot in other]:
                raise token.error("IF must end in THEN and leave equal stack types on both branches")
            stack[:] = [a.merge(b) for a, b in zip(stack, other, strict=True)]
            instructions.append(Located(Conditional(yes, no), token))
            host_uses.update(dict.fromkeys((*yes_host, *no_host)))
            continue
        if not native_opcodes and name in NATIVE_OPCODES and name not in words:
            raise token.error(f"{token.text!r} requires REQUIRE BSV")
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
            require_callable(instruction, token)
            transform(stack, instruction.slots(instruction.takes), instruction.slots(instruction.gives), token)
            host_uses.update(dict.fromkeys(instruction.host_uses))
            if instruction.location == "build":
                host_uses[token] = None
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
    if name in BSV_SOURCE | FILE_EXT_SOURCE:
        raise token.error(f"{token.text!r} is a source declaration and cannot be used inside a definition")
    raise unavailable(token)


def require_script(word):
    if word.location == "build":
        raise CompileError(f"{word.name!r} is a build-time Script constructor")
    if word.location != "script":
        uses = ", ".join(f"{token.text} ({token.location})" for token in dict.fromkeys(word.host_uses))
        suffix = f": {uses}" if uses else ""
        raise CompileError(f"host-only words cannot compile to BSV Script{suffix}")


def require_callable(word, at):
    if isinstance(word, Word) and word.lock is not None:
        raise at.error(f"{at.text!r} is a lock entry and cannot be called as a word")


def check_word(words, at, takes, gives):
    word = words.get(at.name)
    if word is None:
        raise at.error(f"undefined worker or join word {at.text!r}")
    require_callable(word, at)
    try:
        require_script(word)
    except CompileError as error:
        raise at.error(str(error)) from error
    if (word.takes, word.gives) != (takes, gives):
        raise at.error(f"{at.text!r} requires signature {takes} -- {gives}")
    return word


class SourceCompiler:
    def __init__(self, source, *, vocabulary=None, stack_types=TYPES, backend=None, source_path=None, bindings=None):
        self.source = source
        self.tokens = None
        self.words = dict(vocabulary or {})
        self.definitions = {}
        self.backend = backend
        self.root_source = Path(source_path).resolve() if source_path is not None else None
        self.source_path = None
        self.active_files = []
        self.loaded_files = set()
        self.imported_words = {}
        self.libraries = {}
        self.stack_types = stack_types
        self.ranges = {}
        self.effects = {}
        self.bindings = {name.casefold(): value for name, value in (bindings or {}).items()}
        self.work = {}
        self.gate = None
        self.join = None
        self.operator = None
        self.recovery = None
        self.independent = []
        self.workflow_input = None
        self.stages = []
        self.relation = None
        self.read_source(source, self.root_source)
        if self.bindings:
            raise CompileError(f"unknown byte parameters: {', '.join(sorted(self.bindings))}")
        if self.effects:
            at, _, _ = next(iter(self.effects.values()))
            raise at.error(f"stack effect for {at.text!r} has no following definition")

    @property
    def optional_wordsets(self):
        return OPTIONAL_WORDSETS

    @property
    def library_imports(self):
        return tuple(self.libraries[name] for name in sorted(self.libraries))

    @property
    def native_opcodes(self):
        return "std/bsv" in self.libraries or getattr(self.tokens, "module", None) == "std/bsv"

    def read_source(self, source, path, label=None):
        previous_tokens, previous_path = self.tokens, self.source_path
        self.tokens, self.source_path = Tokens(source, label), path
        if path is not None:
            self.active_files.append(path)
        try:
            for token in self.tokens:
                try:
                    self.declaration(token)
                except RecursionError as error:
                    raise token.error("source loading or conditional nesting exceeds the compiler's recursion limit") from error
        finally:
            if path is not None:
                self.active_files.pop()
            self.tokens, self.source_path = previous_tokens, previous_path

    def require_file(self, at):
        filename = self.tokens.filename(at)
        directory = self.source_path.parent if self.source_path is not None else Path.cwd()
        try:
            path, name, library = required_source(filename, directory)
        except (OSError, ValueError) as error:
            raise at.error(f"could not resolve required file {filename!r}: {error}") from error
        if path in self.loaded_files:
            return
        if path in self.active_files:
            cycle = " -> ".join(item.name for item in (*self.active_files, path))
            raise at.error(f"REQUIRE cycle: {cycle}")
        if library is not None and library.backend is not None and self.backend != library.backend:
            raise at.error(f"{filename!r} requires the {library.backend} backend")
        try:
            raw = read_library(name) if library is not None else path.read_bytes()
            content = raw.decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise at.error(f"could not read required file {filename!r}: {error}") from error
        # Diagnostics use catalog names for bundled files and source paths for other files.
        if name is None:
            base = self.root_source.parent if self.root_source is not None else Path.cwd()
            name = Path(relpath(path, base)).as_posix()
        backend_words = ({word: primitive for word, primitive in p256_vocabulary().items() if word not in self.words}
                         if name == "std/p256" else {})
        self.words.update(backend_words)
        try:
            self.read_source(content, path, name)
        finally:
            for spelling, primitive in backend_words.items():
                if self.words[spelling] is primitive:
                    del self.words[spelling]
        interface = None
        if library is not None:
            for export in library.exports:
                entry = export.name
                word, defined = self.words.get(entry), self.definitions.get(entry)
                if defined is None or defined.module != name:
                    raise at.error(f"{filename!r} does not define the declared export {entry!r}")
                if (word.takes, word.gives) != (export.takes, export.gives):
                    raise defined.error(f"{entry!r} does not match its public stack effect "
                                        f"{export.takes} -- {export.gives}")
                for spelling in export.names:
                    self.words[spelling] = word
                    self.definitions[spelling] = defined
                    self.imported_words[spelling] = (name, export)
            interface = interface_digest(name, library)
        self.loaded_files.add(path)
        self.libraries[name] = LibraryImport(name, sha256(raw).hexdigest(), interface)

    def effect(self, at):
        name = required(self.tokens, at, "definition name")
        if name.name.startswith("bsv-"):
            raise name.error(f"the bsv- prefix is reserved by 4thGraph: {name.text!r}")
        if name.name in self.effects or name.name in CONTROL | BSV_SOURCE | FILE_EXT_SOURCE:
            raise name.error(f"invalid or duplicate effect declaration for {name.text!r}")
        before, after = [], []
        current = before
        for token in self.tokens:
            if token.name == ";" and current is after:
                self.effects[name.name] = name, tuple(before), tuple(after)
                return
            if token.name == "--" and current is before:
                current = after
            elif token.name in self.stack_types or token.name in self.ranges:
                current.append(token.name)
            else:
                raise token.error("expected a stack type, '--', or the closing ';'")
        raise at.error("unterminated BSV-EFFECT: declaration")

    def declare_range(self, at):
        name = identifier(self.tokens, at, "range name")
        if name in self.stack_types or name in self.ranges:
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

    def declare_bytes_param(self, at):
        name = named_token(self.tokens, at, "byte parameter name")
        if name.name.startswith("bsv-") or name.name in self.words or name.name in BUILTIN_WORDS:
            raise name.error(f"invalid or duplicate byte parameter {name.text!r}")
        width = required(self.tokens, at, "byte parameter size")
        try:
            size = range_bound(width.text)
        except ValueError as error:
            raise width.error(str(error)) from error
        if not 0 <= size < 1 << 32:
            raise width.error("byte parameter size must be an unsigned 32-bit integer")
        end = required(self.tokens, at, "';'")
        if end.name != ";":
            raise end.error("expected ';' after byte parameter size")
        value = self.bindings.pop(name.name, None)
        if value is None:
            raise name.error(f"missing binding for byte parameter {name.text!r}")
        if not isinstance(value, bytes) or len(value) != size:
            raise name.error(f"byte parameter {name.text!r} requires exactly {size} bytes")
        body = (Located(Literal("bytes", value), name),)
        self.words[name.name] = Word((), ("bytes",), body, "script", name=name.name)
        self.definitions[name.name] = name

    def define_lock(self, at):
        if self.backend == WALLET_BACKEND:
            raise at.error("lock: requires a spend-time source")
        name = named_token(self.tokens, at, "lock name")
        if name.name.startswith("bsv-") or name.name in CONTROL | BSV_SOURCE | FILE_EXT_SOURCE:
            raise name.error(f"invalid or reserved lock name {name.text!r}")
        terms = self.tokens.stack_effect(require_separator=False)
        if terms is None:
            raise name.error("expected named lock inputs in parentheses")
        inputs = {}
        takes = []
        for index, term in enumerate(terms):
            label, _, kind = term.partition(":")
            if (not re.fullmatch(r"[a-z][a-z0-9_-]*", label) or label in inputs or label in BUILTIN_WORDS
                    or label.startswith("bsv-") or label in self.words
                    or kind not in self.stack_types and kind not in self.ranges):
                raise name.error(f"invalid or duplicate named lock input {term!r}")
            ranges = (self.ranges[kind],) if kind in self.ranges else ()
            inputs[label] = Word((), (kind,), (Located(NamedInput(index), name),), "script", ranges=ranges)
            takes.append(kind)
        stack = []
        instructions, host_uses, stop = body(self.tokens, stack, self.words | inputs, at, self.ranges,
                                            native_opcodes=self.native_opcodes)
        if stop.name != ";":
            raise stop.error(f"unexpected {stop.text!r}, expected ';'")
        if host_uses:
            token = host_uses[0]
            raise token.error(f"host-only word {token.text!r} cannot run in a lock")
        if stack and [slot.kind for slot in stack] != ["cell"]:
            raise name.error("a lock must leave one cell or end with verify")
        takes = tuple(takes)
        ranges = tuple(self.ranges[kind] for kind in dict.fromkeys(takes) if kind in self.ranges)
        lock = plan_lock(instructions, takes, name)
        self.words[name.name] = Word(takes, ("cell",), instructions, "script", name=name.name, ranges=ranges, lock=lock)
        self.definitions[name.name] = name
        self.imported_words.pop(name.name, None)

    def define(self, at):
        name = required(self.tokens, at, "definition name")
        declaration = self.effects.pop(name.name, None)
        if name.name.startswith("bsv-") or name.name in CONTROL | BSV_SOURCE | FILE_EXT_SOURCE:
            raise name.error(f"invalid or reserved definition name {name.text!r}")
        if declaration is not None:
            _, takes, gives = declaration
        else:
            terms = self.tokens.stack_effect()
            if terms is None:
                raise name.error("expected a stack effect comment after the definition name")
            if terms.count("--") != 1 or any(kind not in self.stack_types and kind not in self.ranges
                                             for kind in terms if kind != "--"):
                raise name.error("stack effect requires declared types separated by exactly one '--'")
            separator = terms.index("--")
            takes, gives = tuple(terms[:separator]), tuple(terms[separator + 1:])
        ranges = tuple(self.ranges[kind] for kind in dict.fromkeys((*takes, *gives)) if kind in self.ranges)
        signature = Word(takes, gives, (), "script", ranges=ranges)
        stack = list(signature.slots(takes))
        instructions, host_uses, stop = body(self.tokens, stack, self.words, at, self.ranges,
                                            native_opcodes=self.native_opcodes)
        if stop.name != ";":
            raise stop.error(f"unexpected {stop.text!r}, expected ';'")
        outputs = signature.slots(gives)
        if len(stack) != len(outputs) or not all(value.within(target) for value, target in zip(stack, outputs, strict=True)):
            actual = tuple(slot.describe() for slot in stack)
            expected = tuple(slot.describe() for slot in outputs)
            raise name.error(f"body leaves {actual}, declared {gives} with ranges {expected}")
        location = "host" if host_uses else "script"
        if self.backend == WALLET_BACKEND:
            location = "build"
        self.words[name.name] = Word(takes, gives, instructions, location, host_uses, name.name, ranges)
        self.definitions[name.name] = name
        self.imported_words.pop(name.name, None)

    def declaration(self, token):
        tokens = self.tokens
        match token.name:
            case "require":
                self.require_file(token)
            case "bsv-effect:":
                self.effect(token)
            case "range:":
                self.declare_range(token)
            case "bytes-param:":
                self.declare_bytes_param(token)
            case "lock:":
                self.define_lock(token)
            case ":":
                self.define(token)
            case "work:":
                name = named_token(tokens, token, "work step")
                if name.name in self.work or name.name in RESERVED_STEPS:
                    raise name.error(f"invalid or duplicate work step {name.text!r}")
                input_name = named_token(tokens, token, "input name")
                word = check_word(self.words, required(tokens, token, "worker word"), ("u32",), ("u32",))
                owner = identifier(tokens, token, "signer role")
                self.work[name.name] = Work(name.name, input_name.name, word, owner, name, input_name)
                end_declaration(tokens, token)
            case "gate:":
                if self.gate is not None:
                    raise token.error("expected at most one gate")
                name = named_token(tokens, token, "gate step")
                input_name = named_token(tokens, token, "input name")
                word = check_word(self.words, required(tokens, token, "gate word"), ("u32",), ("cell",))
                owner = identifier(tokens, token, "signer role")
                self.gate = Work(name.name, input_name.name, word, owner, name, input_name)
                end_declaration(tokens, token)
            case "join:":
                if self.join is not None:
                    raise token.error("expected one join")
                name = named_token(tokens, token, "join step")
                left = named_token(tokens, token, "first work step")
                right = named_token(tokens, token, "second work step")
                word = check_word(self.words, required(tokens, token, "join word"), ("u32", "u32"), ("route",))
                self.join = name, left, right, word
                end_declaration(tokens, token)
            case "split-authority:":
                if self.operator is not None:
                    raise token.error("expected one split authority")
                self.operator = identifier(tokens, token, "signer role")
                end_declaration(tokens, token)
            case "recovery:":
                if self.recovery is not None:
                    raise token.error("expected at most one recovery policy")
                height = required(tokens, token, "decimal block height")
                if not re.fullmatch(r"[0-9]{1,9}", height.text) or not 0 < int(height.text) < LOCKTIME_THRESHOLD:
                    raise height.error("recovery height must be a block height from 1 to 499999999")
                self.recovery = Recovery(int(height.text), identifier(tokens, token, "recovery signer role"))
                end_declaration(tokens, token)
            case "workflow-input:":
                if self.workflow_input is not None:
                    raise token.error("expected one workflow input")
                self.workflow_input = named_token(tokens, token, "workflow input")
                kind = required(tokens, token, "workflow input type")
                if kind.name != "u32":
                    raise kind.error("workflow input must be u32")
                end_declaration(tokens, token)
            case "stage:":
                labels = ("stage name", "Script word", "input value", "output value", "signer role")
                self.stages.append(tuple(named_token(tokens, token, label) for label in labels))
                end_declaration(tokens, token)
            case "relation:" | "verify:":
                if "std/verify" not in self.libraries:
                    raise token.error("relation: requires 'REQUIRE stdlib/verify.fth'")
                if self.relation is not None:
                    raise token.error("expected one relation declaration")
                transition = named_token(tokens, token, "transition word")
                route = named_token(tokens, token, "route word")
                self.relation = (transition, route)
                end_declaration(tokens, token)
            case "independent-submit:" | "independent-submit":
                self.independent.append((identifier(tokens, token, "transaction step"), token.line))
                end_declaration(tokens, token)
            case name if name in self.work or self.gate is not None and name == self.gate.name:
                # The original prototype spelled this declaration "<step> independent-submit".
                directive = required(tokens, token, "independent-submit")
                if directive.name != "independent-submit":
                    raise directive.error("expected independent-submit after the work step")
                self.independent.append((name, token.line))
            case name if name in self.words or name in PRIMITIVES or name in SHUFFLES or name in HOST_WORDS \
                    or name in NAMED_LITERALS:
                raise token.error("top-level execution is unavailable in a Script build")
            case _:
                raise unavailable(token)

    def require_workflow_declarations(self):
        if self.relation:
            raise self.relation[0].error("use the relation compiler for a relation: declaration")

    def program(self):
        self.require_workflow_declarations()
        if self.workflow_input is not None or self.stages:
            raise CompileError("stage workflows require the workflow planner")
        if len(self.work) != 2 or self.join is None or self.operator is None:
            raise CompileError("expected two work declarations, one join and one split authority")
        name, left, right, word = self.join
        if name.name in self.work or name.name in RESERVED_STEPS:
            raise name.error("join must have a distinct step name")
        for operand in (left, right):
            if operand.name not in self.work:
                raise operand.error(f"no producer for {operand.text!r}")
        if left.name == right.name:
            raise right.error(f"illegal repeated consumption of {right.text!r}")
        step_names = set(self.work)
        if self.gate is not None:
            if self.gate.name in step_names | RESERVED_STEPS | {name.name}:
                raise self.gate.declaration.error(f"invalid or duplicate gate step {self.gate.name!r}")
            step_names.add(self.gate.name)
        for step, line in self.independent:
            if step not in step_names:
                raise CompileError(f"line {line}: unknown gate or work step {step!r}")
        return Program(self.words, (self.work[left.name], self.work[right.name]), word, name.name, self.operator,
                       tuple(self.independent), self.optional_wordsets, name, (left, right),
                       self.gate, self.recovery, self.library_imports)

    def workflow(self):
        self.require_workflow_declarations()
        if self.workflow_input is None:
            if self.stages:
                raise self.stages[0][0].error("staged workflow needs a workflow-input: declaration")
            raise CompileError("expected a workflow-input: declaration")
        if self.work or self.join or self.operator or self.gate:
            raise self.workflow_input.error("staged workflows cannot contain parallel work or join declarations")
        if len(self.stages) < 2:
            raise self.workflow_input.error("a workflow needs at least two stages")
        stages = {}
        names = set(RESERVED_STEPS)
        for name, entry, source, result, owner in self.stages:
            if name.name in names:
                raise name.error(f"duplicate or reserved stage {name.text!r}")
            names.add(name.name)
            word = self.words.get(entry.name)
            if word is None:
                raise entry.error(f"undefined Script word {entry.text!r}")
            require_callable(word, entry)
            try:
                require_script(word)
            except CompileError as error:
                raise entry.error(str(error)) from error
            if len(word.takes) != 1 or len(word.gives) != 1:
                raise entry.error("workflow words must consume and produce exactly one value")
            stages[name.name] = Stage(name.name, word, source, result, owner.name, name)
        workflow = Workflow(self.workflow_input, tuple(stages.values()), tuple(self.independent), self.recovery,
                            self.library_imports)
        ordered = tuple(stages[stage.name] for stage in workflow.stage_graph().stages)
        for stage, expected in zip(ordered, (*("u32" for _ in ordered[:-1]), "route"), strict=True):
            if stage.word.gives != (expected,):
                raise stage.result.error(f"expected a chain of u32 states ending in route, found {stage.word.gives[0]}")
        for step, line in self.independent:
            if step not in stages:
                raise CompileError(f"line {line}: unknown workflow stage {step!r}")
        return Workflow(self.workflow_input, ordered, workflow.independent, workflow.recovery, workflow.libraries)


def end_declaration(tokens, at):
    end = tokens.peek()
    if end is not None and end.name == ";":
        next(tokens)
    elif at.name not in (*LEGACY_IMPLICIT_END, "independent-submit"):
        raise (end or at).error(f"expected ';' after {at.text!r}")


WORKFLOW_MODES = ("fused", "serial", "atomic")


def workflow_blockers(program, mode, available_authorizers):
    if mode != "serial" and len(program.stages) != 2:
        stage = program.stages[2].declaration
        return [{"code": "unsupported_stage_count", "line": stage.line,
                 "message": f"{stage.location}: {mode} supports two stages; use serial for a longer chain"}]
    required_roles = ((program.stages[0].owner,) if mode == "serial"
                      else tuple(dict.fromkeys(stage.owner for stage in program.stages)))
    reasons = [
        {"code": "unavailable_authorizer", "role": role,
         "message": f"{role} must be available for the first spend in the {mode} layout"}
        for role in required_roles if role not in available_authorizers
    ]
    if mode != "serial":
        reasons.extend(
            {"code": "independent_submit", "stage": step, "line": line,
             "message": f"line {line}: independent-submit {step} requires a separate transaction"}
            for step, line in program.independent
        )
    return reasons


def plan_workflow(program, mode, *, available_authorizers=None):
    available = {stage.owner for stage in program.stages} if available_authorizers is None else set(available_authorizers)
    if mode == "auto":
        mode = "serial" if workflow_blockers(program, "fused", available) else "fused"
    if mode not in WORKFLOW_MODES:
        raise CompileError("workflow mode must be fused, serial or atomic")
    blockers = workflow_blockers(program, mode, available)
    if blockers:
        raise CompileError("; ".join(reason["message"] for reason in blockers))
    return workflow_layout(program, mode)


def workflow_layout(program, mode):
    graph = program.stage_graph()
    first, second = graph.stages[:2]
    if mode == "fused":
        templates = (
            Template(mode, (ParentOutput("deploy", 0),), tuple(dict.fromkeys((first.authorizer, second.authorizer))),
                     ("terminal", "receipt"), (first.name, second.name)),
        )
        deployment, reasons = ("state-lock",), ()
    if mode == "serial":
        templates = tuple(
            Template(stage.name, (ParentOutput(parent, 0),), (stage.authorizer,),
                     ("terminal", "receipt") if stage is graph.stages[-1] else ("state",), (stage.name,))
            for stage, parent in zip(graph.stages, ("deploy", *(node.name for node in graph.stages[:-1])), strict=True)
        )
        deployment = ("state-lock",)
        reasons = ("materialize each u32 result in the next transaction's input",)
    if mode == "atomic":
        templates = (
            Template(mode, (ParentOutput("deploy", 0), ParentOutput("deploy", 1)),
                     (first.authorizer, second.authorizer), ("terminal", "receipt"), (first.name, second.name)),
        )
        deployment = ("state-lock", "route-lock")
        reasons = ("check each stage in a separate input and bind both inputs to the same deployment and outputs",)
    return Plan(mode, program, templates, (), reasons, deployment, graph)


def parse(source, *, source_path=None):
    return SourceCompiler(source, source_path=source_path).program()


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
    graph = program.stage_graph()
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
    return Plan(mode, program, templates, tuple(blockers), tuple(reasons), stage_graph=graph)


def run_primitive(instruction, args, *, context=None, checksig=None):
    if instruction.location == "host":
        return instruction.run(context, *args)
    if instruction.requires_checksig:
        return instruction.run(checksig, *args)
    return instruction.run(*args)


def evaluate(word, *values, context=None, checksig=None):
    if len(values) != len(word.takes):
        raise ValueError("incorrect argument count for Forth word")
    for kind, slot, value in zip(word.takes, word.slots(word.takes), values, strict=True):
        bounds = slot.bounds
        if slot.kind in NUMERIC_TYPES and (type(value) is not int or
                                          bounds is not None and not bounds[0] <= value <= bounds[1]):
            raise ValueError(f"argument is out of range for {kind}")
        if kind == "bytes" and not isinstance(value, bytes):
            raise ValueError("expected a bytes argument")
    if word.lock is not None:
        return word.lock.run(range(len(values)), values, checksig)
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
            stack[start:] = run_primitive(instruction, stack[start:], context=context, checksig=checksig)
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


def bounded_expansion(*roots, limit):
    """Count expanded calls and branches without materializing their instructions."""
    sizes = {}
    pending = [(body, None) for body in roots]
    while pending:
        body, children = pending.pop()
        if id(body) in sizes:
            continue
        if children is None:
            children = []
            for item in body:
                node = item.instruction if isinstance(item, Located) else item
                if isinstance(node, Word):
                    children.append(node.body)
                elif isinstance(node, Conditional):
                    children.extend((node.yes, node.no))
            pending.append((body, children))
            pending.extend((child, None) for child in children if id(child) not in sizes)
        else:
            nodes = (item.instruction if isinstance(item, Located) else item for item in body)
            cost = sum(node.expansion_cost if isinstance(node, Primitive) else 1 for node in nodes)
            sizes[id(body)] = min(limit + 1, cost + sum(sizes[id(child)] for child in children))
    return min(limit + 1, sum(sizes[id(body)] for body in roots))


@dataclass(frozen=True)
class LockStep:
    node: Literal | Primitive | LockBranch
    args: tuple[int, ...]
    results: tuple[int, ...]
    source: Token | None


@dataclass(frozen=True)
class LockBlock:
    steps: tuple[LockStep, ...]
    returns: tuple[int, ...]

    def uses_before(self, slot):
        values = {*self.returns, *(arg for step in self.steps for arg in step.args)}
        return {value for value in values if value < slot}

    def run(self, inputs, values, checksig):
        slots = dict(zip(inputs, values, strict=True))
        for step in self.steps:
            node = step.node
            outputs = ((node.value,) if isinstance(node, Literal)
                       else run_primitive(node, (slots[index] for index in step.args), checksig=checksig))
            slots.update(zip(step.results, outputs, strict=True))
        return tuple(slots[index] for index in self.returns)


@dataclass(frozen=True)
class LockBranch:
    inputs: tuple[int, ...]
    yes: LockBlock
    no: LockBlock

    location = "script"
    requires_checksig = True

    def run(self, checksig, *values):
        branch = self.yes if values[-1] else self.no
        return branch.run(self.inputs, values[:-1], checksig)


def plan_lock_block(instructions, stack, next_slot):
    steps = []
    for node, source in expanded(instructions):
        if isinstance(node, Conditional):
            flag = stack.pop()
            before_branch = next_slot
            yes, next_slot = plan_lock_block(node.yes, list(stack), next_slot)
            no, next_slot = plan_lock_block(node.no, list(stack), next_slot)
            inputs = tuple(sorted(yes.uses_before(before_branch) | no.uses_before(before_branch)))
            results = tuple(range(next_slot, next_slot + len(yes.returns)))
            steps.append(LockStep(LockBranch(inputs, yes, no), (*inputs, flag), results, source))
            stack[:] = results
            next_slot += len(results)
            continue
        if isinstance(node, NamedInput):
            stack.append(node.index)
            continue
        if isinstance(node, Shuffle):
            count, order, _ = SHUFFLES[node.name]
            entries = stack[-count:]
            stack[-count:] = [entries[i] for i in order]
            continue
        arity, outputs = (0, 1) if isinstance(node, Literal) else (len(node.takes), len(node.gives))
        start = len(stack) - arity
        results = tuple(range(next_slot, next_slot + outputs))
        steps.append(LockStep(node, tuple(stack[start:]), results, source))
        stack[start:] = results
        next_slot += outputs
    return LockBlock(tuple(steps), tuple(stack)), next_slot


def plan_lock(instructions, takes, at):
    if bounded_expansion(instructions, limit=MAX_EXPANSION) > MAX_EXPANSION:
        raise at.error(f"lock {at.text!r} exceeds the {MAX_EXPANSION}-operation expansion budget")
    block, _ = plan_lock_block(instructions, [], len(takes))
    if block.returns:
        return block
    if not block.steps or block.steps[-1].node is not PRIMITIVES["op_verify"]:
        raise at.error("a lock must leave one cell or end with verify")
    # Only a standalone Script entry can use the assertion operand as its final result.
    return LockBlock(block.steps[:-1], block.steps[-1].args)


def check_word_expansion(word, max_expansion):
    if bounded_expansion(word.body, limit=max_expansion) > max_expansion:
        raise CompileError(f"word {word.name!r} exceeds the {max_expansion}-operation expansion budget before lowering")


def lower(word, *, check_input_ranges=True, max_expansion=MAX_EXPANSION):
    if word.lock is not None:
        from fourthgraph.compiler.lowering import compile_word

        return compile_word(word, check_input_ranges=check_input_ranges, max_expansion=max_expansion).script
    require_script(word)
    check_word_expansion(word, max_expansion)
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

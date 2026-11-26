"""Lower bounded Forth u32 arithmetic and route selection to Circom."""

import argparse
from dataclasses import asdict, dataclass
from pathlib import Path

from compiler import MAX_EXPANSION, CompileError, Conditional, Shuffle, SourceCompiler, Token, Word, bounded_expansion, expanded
from stdlib import LibraryImport
from wordsets import U32, Literal, PRIMITIVES, SHUFFLES

BIT_DECOMPOSITION = """pragma circom 2.2.2;

template Bits(width) {
    signal input value;
    signal output high;
    signal bit[width];
    var reconstructed = 0;
    for (var i = 0; i < width; i++) {
        bit[i] <-- (value >> i) & 1;
        bit[i] * (bit[i] - 1) === 0;
        reconstructed += bit[i] * (1 << i);
    }
    value === reconstructed;
    high <== bit[width - 1];
}
"""
MAX_STEPS = 128
MAX_WIRES = 256


@dataclass(frozen=True)
class CircuitProgram:
    transition: Word
    route: Word
    selection: str
    definitions: tuple[Token, Token]
    libraries: tuple[LibraryImport, ...] = ()

    def describe(self):
        spec = {
            "selection": self.selection,
            "entries": {
                role: {"word": word.name, "takes": word.takes, "gives": word.gives,
                       "line": at.line, "column": at.column, **({"module": at.module} if at.module else {})}
                for role, word, at in zip(("transition", "route"), (self.transition, self.route),
                                          self.definitions, strict=True)
            },
        }
        if self.libraries:
            spec["libraries"] = tuple(map(asdict, self.libraries))
        return spec


@dataclass(frozen=True)
class Wire:
    kind: str
    expr: str
    literal: int | None = None
    flag: str | None = None

    @classmethod
    def constant(cls, kind, value):
        return cls(kind, str(value), literal=value)


class CircuitBuilder:
    def __init__(self):
        self.lines = []
        self.count = 0
        self.steps = 0
        self.wires = 7  # Wire zero, inputs, outputs and the binding product.

    def add(self, row):
        self.lines.append(f"    {row}")

    def symbol(self, label):
        self.count += 1
        return f"{label}{self.count}"

    def signal(self, kind, expr):
        self.wires += 1
        name = self.symbol("wire")
        self.add(f"signal {name} <== {expr};")
        return Wire(kind, name)

    def bits(self, expr, width):
        self.wires += width + 2
        name = self.symbol("bits")
        self.add(f"component {name} = Bits({width});")
        self.add(f"{name}.value <== {expr};")
        return f"{name}.high"

    def add_u32(self, left, right):
        # The sum and the bounded result plus a binary carry are below 2^33.
        # Their equality in BN254 also holds as integers.
        total = self.signal("sum", f"{left.expr} + {right.expr}")
        carry = self.symbol("carry")
        self.wires += 1
        self.add(f"signal {carry} <-- {total.expr} >> 32;")
        self.add(f"{carry} * ({carry} - 1) === 0;")
        value = self.signal("u32", f"{total.expr} - {carry} * {U32}")
        self.bits(value.expr, 32)
        return value

    def less_u32(self, left, right):
        # Bit 32 is set exactly when left >= right. Forth true is -1.
        high = self.bits(f"{left.expr} + {U32} - {right.expr}", 33)
        truth = self.signal("flag", f"1 - {high}")
        return Wire("cell", f"-{truth.expr}", flag=truth.expr)

    def select(self, condition, yes, no):
        if yes == no:
            return yes
        value = self.signal(yes.kind, f"{condition} * ({yes.expr} - ({no.expr})) + ({no.expr})")
        if yes.flag and no.flag:
            return Wire(value.kind, value.expr, flag=f"(-{value.expr})")
        return value

    def block(self, body, stack):
        for node, token in expanded(body):
            self.steps += 1
            if self.steps > MAX_STEPS:
                raise token.error("expanded circuit exceeds 128 operations")
            if isinstance(node, Literal) and isinstance(node.value, int):
                stack.append(Wire.constant(node.kind, node.value))
            elif isinstance(node, Shuffle):
                arity, order, _ = SHUFFLES[node.name]
                suffix = stack[-arity:]
                stack[-arity:] = [suffix[i] for i in order]
            elif isinstance(node, Conditional):
                guard = stack.pop()
                if guard.flag is None and guard.literal is None:
                    raise token.error("circuit IF requires a literal or a u32< comparison")
                yes, no = list(stack), list(stack)
                self.block(node.yes, yes)
                self.block(node.no, no)
                if guard.literal is not None:
                    stack[:] = yes if guard.literal else no
                else:
                    stack[:] = [self.select(guard.flag, a, b) for a, b in zip(yes, no, strict=True)]
            elif node is PRIMITIVES["cell>u32"] and stack[-1].literal is not None:
                stack[-1] = Wire.constant("u32", stack[-1].literal % U32)
            elif node is PRIMITIVES["u32+"]:
                right, left = stack.pop(), stack.pop()
                stack.append(self.add_u32(left, right))
            elif node is PRIMITIVES["u32<"]:
                right, left = stack.pop(), stack.pop()
                stack.append(self.less_u32(left, right))
            else:
                raise token.error(f"{token.text!r} is outside the bounded circuit word set")
            if self.wires > MAX_WIRES:
                raise token.error(f"generated circuit exceeds the {MAX_WIRES}-wire budget")


def select_circuit(frontend, entries=None):
    names = None if entries is None else tuple(name.casefold() for name in entries)
    if names is not None and len(names) != 2:
        raise CompileError("circuit entries require a transition word and a route word")
    if frontend.relation:
        transition, route = frontend.relation
        if (frontend.workflow_input or frontend.stages or frontend.work or frontend.gate or frontend.join
                or frontend.operator or frontend.independent or frontend.recovery):
            raise transition.error("relation: cannot be combined with transaction workflow declarations")
        declared = (transition.name, route.name)
        if names is not None and names != declared:
            raise transition.error(f"circuit entries must match relation: {declared}")
        names, selection = declared, "relation"
    elif frontend.workflow_input is not None or frontend.stages:
        stages = frontend.workflow().stages
        if len(stages) != 2:
            raise stages[2].declaration.error("the circuit backend requires one transition and one route stage")
        workflow_names = tuple(stage.word.name for stage in stages)
        if names is not None and names != workflow_names:
            raise stages[0].declaration.error(f"circuit entries must match the declared workflow words {workflow_names}")
        names, selection = workflow_names, "workflow"
    elif names is None:
        names, selection = ("advance", "decide"), "legacy"
    else:
        selection = "explicit"
    effects = ((("u32",), ("u32",)), (("u32",), ("route",)))
    words, definitions = [], []
    for i, (name, (takes, gives)) in enumerate(zip(names, effects, strict=True)):
        word, at = frontend.words.get(name), frontend.definitions.get(name)
        if word is None or at is None:
            if frontend.relation:
                raise frontend.relation[i].error(f"undefined circuit word {name!r}")
            raise CompileError(f"undefined circuit word {name!r}")
        if (word.takes, word.gives) != (takes, gives):
            raise at.error(f"circuit word {name!r} requires stack effect {' '.join(takes)} -- {' '.join(gives)}")
        words.append(word)
        definitions.append(at)
    return CircuitProgram(*words, selection, tuple(definitions), frontend.library_imports)


def circuit_words(source):
    program = select_circuit(SourceCompiler(source.decode()))
    return program.transition, program.route


def compile_circuit(source, *, entries=None, source_path=None):
    return emit_circuit(select_circuit(SourceCompiler(source.decode(), source_path=source_path), entries))


def emit_circuit(program, *, max_expansion=MAX_EXPANSION):
    if bounded_expansion(program.transition.body, program.route.body, limit=max_expansion) > max_expansion:
        raise program.definitions[0].error(f"circuit exceeds the {max_expansion}-operation expansion budget before lowering")
    builder = CircuitBuilder()
    builder.bits("current", 32)
    stack = [Wire("u32", "current")]
    builder.block(program.transition.body, stack)
    next_state, = stack
    builder.block(program.route.body, stack)
    route, = stack
    builder.add(f"next <== {next_state.expr};")
    builder.add(f"route <== {route.expr};")
    builder.add("signal bindingProduct <== bindLo * bindHi;")
    code = [
        BIT_DECOMPOSITION, "template Workflow() {",
        "    signal input current;", "    signal input bindLo;", "    signal input bindHi;",
        "    signal output next;", "    signal output route;", *builder.lines, "}", "",
        "component main {public [current, bindLo, bindHi]} = Workflow();", "",
    ]
    return "\n".join(code).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--entries", nargs=2, metavar=("TRANSITION", "ROUTE"), help="select two Forth words")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        code = compile_circuit(args.source.read_bytes(), entries=args.entries, source_path=args.source)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(code)
    except (OSError, ValueError) as error:
        parser.error(f"{args.source}: {error}")


if __name__ == "__main__":
    main()

"""Execute Forth stage constructors and build a checked 4thGraph workflow plan."""

import argparse
from collections import defaultdict
from dataclasses import dataclass, field as data_field, replace
from graphlib import CycleError, TopologicalSorter
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from fourthgraph.compiler.source import CompileError, Conditional, SourceCompiler, Stage, Token, Word, Workflow, require_script
from fourthgraph.bsv.transaction import (
    ANYONECANPAY, CHRONICLE, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_TYPES,
)
from fourthgraph.workflow.protocol import TARGETS
from fourthgraph.compiler.wordsets import CORE_EXT_SCRIPT, CORE_SCRIPT, NAMED_LITERALS, Literal, cell_literal
from fourthgraph.workflow.workflow_contract import WorkflowContracts


SELECTORS = ("ordered", "range", "current", "paired", "unselected")
POLICIES = ("direct-script", "proof-required", "groth16-required")
AMOUNTS = ("none", "signed", "parent")
SERIAL_MODES = {(0x41,): "forkid", (0x61,): "chronicle", (0x41, 0x61): "both"}
SYMBOL = re.compile(r"[a-z][a-z0-9_-]*")
U32_LIMIT = 1 << 32
RULE_SYNTAX = {"if", "else", "then", ";", "(", "\\"}
RULE_BUILTINS = CORE_SCRIPT | CORE_EXT_SCRIPT | NAMED_LITERALS.keys() | RULE_SYNTAX | {
    "cell>u32", "u32>cell", "u32+", "u32<",
}


def field(row):
    value = next(row, None)
    if value is None:
        raise ValueError("incomplete record")
    return value


@dataclass(frozen=True)
class Selection:
    kind: str
    minimum: int
    maximum: int | None
    index_range: tuple[int, int] | None = None

    @classmethod
    def read(cls, row, side):
        kind, minimum, maximum, first, limit = (int(field(row)) for _ in range(5))
        if not 0 <= kind < len(SELECTORS):
            raise ValueError(f"invalid {side} selector")
        kind = SELECTORS[kind]
        if not 0 <= minimum <= U32_LIMIT or (maximum != -1 and not max(1, minimum) <= maximum <= U32_LIMIT):
            raise ValueError(f"invalid {side} count interval")
        if (side, kind) in {("input", "paired"), ("input", "unselected"), ("output", "current")}:
            raise ValueError(f"{kind} selector is unavailable on the {side} side")
        if kind == "range":
            if not 0 <= first < limit <= U32_LIMIT or (maximum != -1 and first >= maximum):
                raise ValueError(f"invalid {side} index interval")
        elif (first, limit) != (0, 0):
            raise ValueError(f"unexpected {side} index interval for {kind}")
        if kind == "unselected" and (minimum, maximum) != (0, -1):
            raise ValueError("unselected outputs cannot constrain their count")
        return cls(kind, minimum, None if maximum == -1 else maximum,
                   (first, limit) if kind == "range" else None)

    @property
    def bounds_count(self):
        return self.minimum != 0 or self.maximum is not None

    def check_resources(self, side, resources):
        if self.maximum is not None and len(resources) > self.maximum:
            raise ValueError(f"too many tracked {side}s for the count interval")
        if self.kind in {"range", "current", "paired"} and len(resources) > 1:
            raise ValueError(f"{self.kind} can select only one tracked {side}")
        if self.kind == "unselected" and resources:
            raise ValueError("unselected outputs cannot produce tracked resources")

    def check_coverage(self, flag, side):
        base = flag & 31
        if side == "input":
            if flag & ANYONECANPAY and (self.kind != "current" or self.bounds_count):
                raise ValueError("ANYONECANPAY authenticates only the current input, without an input count")
        elif base == SIGHASH_NONE and self.kind != "unselected":
            raise ValueError("NONE does not authenticate outputs")
        elif base == SIGHASH_SINGLE:
            if self.kind == "unselected" and not (flag & CHRONICLE):
                return
            if self.kind != "paired" or self.bounds_count:
                raise ValueError("SINGLE requires a paired output without an output count constraint")

    def describe(self):
        fields = {"kind": self.kind, "count": [self.minimum, self.maximum]}
        if self.index_range is not None:
            fields["index_range"] = list(self.index_range)
        return fields


def vector(row):
    count = int(field(row))
    if count < 0:
        raise ValueError("negative vector length")
    return tuple(int(field(row)) for _ in range(count))


def resources(items):
    if any(not 0 <= item < U32_LIMIT for item in items) or len(set(items)) != len(items):
        raise ValueError("resource numbers must be distinct unsigned 32-bit integers in each list")
    return items


@dataclass(frozen=True)
class StageRecord:
    name: str
    relation: str
    owner: str
    policy: str
    amount: str
    sighashes: tuple[int, ...]
    input_selection: Selection
    output_selection: Selection
    consumes: tuple[int, ...]
    produces: tuple[int, ...]

    @classmethod
    def read(cls, row):
        name, relation, owner = (field(row).casefold() for _ in range(3))
        if not SYMBOL.fullmatch(name) or name in {"deploy", "split", "fused"} or not SYMBOL.fullmatch(owner):
            raise ValueError(f"invalid stage or role name in {name!r}")
        if not re.fullmatch(r"[a-z][a-z0-9_?+-]*", relation):
            raise ValueError(f"invalid relation word {relation!r}")
        policy, amount = int(field(row)), int(field(row))
        if not 0 <= policy < len(POLICIES) or not 0 <= amount < len(AMOUNTS):
            raise ValueError(f"{name}: unknown proof or amount policy")
        modes = vector(row)
        if not modes or len(set(modes)) != len(modes) or set(modes) - SIGHASH_TYPES:
            raise ValueError(f"{name}: expected a nonempty set of distinct supported sighash bytes")
        ins, outs = Selection.read(row, "input"), Selection.read(row, "output")
        consumed, produced = resources(vector(row)), resources(vector(row))
        if not consumed:
            raise ValueError(f"{name}: a stage must consume at least one tracked resource")
        ins.check_resources("input", consumed)
        outs.check_resources("output", produced)
        for flag in modes:
            try:
                ins.check_coverage(flag, "input")
                outs.check_coverage(flag, "output")
                if amount == 1 and flag & CHRONICLE:
                    raise ValueError("OTDA omits the current prevout amount; require parent-amount evidence")
            except ValueError as exc:
                raise ValueError(f"{name} (sighash 0x{flag:02x}): {exc}") from exc
        return cls(name, relation, owner, POLICIES[policy], AMOUNTS[amount], tuple(sorted(modes)),
                   ins, outs, consumed, produced)


@dataclass(frozen=True)
class Plan:
    roots: tuple[int, ...]
    stages: tuple[StageRecord, ...]
    sources: dict[int, tuple[str | None, int]]
    conflicts: tuple[tuple[int, tuple[str, ...]], ...]
    trace: "SourceTrace | None" = data_field(default=None, repr=False, compare=False)

    @classmethod
    def build(cls, roots, stages):
        if not roots or not stages:
            raise ValueError("expected at least one deployment resource and one stage")
        sources = {item: (None, index) for index, item in enumerate(roots)}
        for stage in stages.values():
            for index, resource in enumerate(stage.produces):
                if resource in sources:
                    raise ValueError(f"{stage.name}: resource {resource} has multiple producers")
                sources[resource] = (stage.name, index)
        dependencies, consumers = {}, defaultdict(list)
        for name in sorted(stages):
            parents = set()
            for resource in stages[name].consumes:
                if resource not in sources:
                    raise ValueError(f"{name}: resource {resource} has no producer")
                consumers[resource].append(name)
                if (parent := sources[resource][0]) is not None:
                    parents.add(parent)
            dependencies[name] = parents

        sorter = TopologicalSorter(dependencies)
        try:
            sorter.prepare()
        except CycleError as exc:
            raise ValueError("stage dependency cycle: " + " -> ".join(exc.args[1])) from exc
        ordered, ancestors = [], {}
        while sorter.is_active():
            ready = tuple(sorted(sorter.get_ready()))
            for name in ready:
                parents = dependencies[name]
                closure = {name, *parents}.union(*(ancestors[parent] for parent in parents))
                seen = set()
                for step in sorted(closure):
                    for item in stages[step].consumes:
                        if item in seen:
                            raise ValueError(f"{name}: required stages compete for resource {item}")
                        seen.add(item)
                ancestors[name] = closure
                ordered.append(stages[name])
            sorter.done(*ready)
        conflicts = tuple((item, tuple(names)) for item, names in sorted(consumers.items()) if len(names) > 1)
        return cls(roots, tuple(ordered), sources, conflicts)

    def describe(self):
        step_ids = {None: 0, **{stage.name: index for index, stage in enumerate(self.stages, 1)}}
        return {
            "schema_version": 1, "deployment": self.roots,
            "steps": [{
                "name": stage.name, "relation": stage.relation, "authorizer": stage.owner,
                "inputs": [(step_ids[parent], slot) for parent, slot in
                           (self.sources[item] for item in stage.consumes)],
                "outputs": stage.produces,
                "input_selection": stage.input_selection.describe(),
                "output_selection": stage.output_selection.describe(),
                "sighash": [f"{flag:02x}" for flag in stage.sighashes],
                "prevout_amount_evidence": stage.amount, "verification_policy": stage.policy,
            } for stage in self.stages],
            "conflicts": [(step_ids[self.sources[item][0]], self.sources[item][1],
                           tuple(step_ids[name] for name in names)) for item, names in self.conflicts],
        }


def parse_plan(text):
    roots, stages = None, {}
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        row = iter(fields[1:])
        try:
            if fields[0] == "roots" and roots is None:
                roots = resources(vector(row))
            elif fields[0] == "stage":
                stage = StageRecord.read(row)
                if stage.name in stages:
                    raise ValueError(f"duplicate stage {stage.name!r}")
                stages[stage.name] = stage
            else:
                raise ValueError("unexpected or duplicate record")
            if next(row, None) is not None:
                raise ValueError("unexpected fields after record")
        except ValueError as exc:
            raise ValueError(f"Forth record {line_number}: {exc}") from exc
    return Plan.build(roots, stages)


class SourceTrace:
    """Source lines, word bindings and single-cell literals observed in Gforth."""

    def __init__(self, records, directory):
        self.lines = defaultdict(dict)
        self.definitions = {}
        self.calls = {}
        self.builtins = {}
        self.changed_syntax = {}
        self.literals = {}
        self.bindings = {}

        paths = {}

        def trace_path(filename):
            if filename not in paths:
                paths[filename] = (directory / os.fsdecode(bytes.fromhex(filename))).resolve()
            return paths[filename]

        for row in records:
            tag, *fields = row.split()
            if tag == "binding":
                xt, stage = fields
                self.bindings[stage.casefold()] = int(xt)
            elif tag == "line":
                number, filename, *content = fields
                path = trace_path(filename)
                line = bytes.fromhex("".join(content))
                if self.lines[path].setdefault(int(number), line) != line:
                    raise CompileError(f"source changed during Forth execution: {path}")
            elif tag == "builtin":
                target, compiled, name = fields
                self.builtins[name] = (int(target), bool(int(compiled)))
            elif tag == "call":
                caller, target, compiled, spelling, column, number, filename = fields
                position = (trace_path(filename), int(number), int(column))
                binding = int(target), bool(int(compiled))
                self.calls[int(caller), position] = binding
                name = bytes.fromhex(spelling).decode(errors="replace").casefold()
                if name in RULE_SYNTAX and name in self.builtins and binding != self.builtins[name]:
                    self.changed_syntax[int(caller)] = (name, position)
            elif tag in ("definition", "literal"):
                *caller, value, column, number, filename = fields
                position = (trace_path(filename), int(number), int(column))
                if tag == "definition":
                    self.definitions[int(value)] = position
                else:
                    self.literals[int(caller[0]), position] = int(value)
            else:
                raise CompileError(f"unexpected Gforth trace record {tag!r}")


class BoundRules(SourceCompiler):
    def __init__(self, source, path, trace):
        self.trace = trace
        self.positions = {}
        super().__init__(source, source_path=path)

    def read_source(self, source, path, label=None):
        # REFILL removes the line terminator. Compare the actual bytes of every
        # line, including those read by nested REQUIRE and multiline comments.
        lines = source.replace("\r\n", "\n").removesuffix("\n").split("\n") if source else []
        actual = self.trace.lines.get(path, {})
        if len(actual) != len(lines) or any(actual.get(i) != line.encode() for i, line in enumerate(lines, 1)):
            raise CompileError(f"rules differ from the source loaded by Gforth: {path}")
        super().read_source(source, path, label)

    def position(self, path, token):
        line = self.trace.lines[path][token.line].decode()
        return path, token.line, len(line[:token.column - 1].encode())

    def define(self, at):
        name = self.tokens.peek()
        super().define(at)
        self.positions[id(self.words[name.name])] = self.position(self.source_path, name)

    def check_word(self, word, xt):
        pending = [(word, xt)]
        seen = set()
        while pending:
            word, xt = pending.pop()
            origin = self.positions[id(word)]
            if self.trace.definitions.get(xt) != origin:
                raise CompileError(f"Gforth bound a different definition of {word.name!r}")
            if xt in self.trace.changed_syntax:
                name, (path, line, column) = self.trace.changed_syntax[xt]
                raise CompileError(f"{path}:{line}:{column + 1}: Gforth redefined the syntax word {name!r}")
            if (id(word), xt) in seen:
                continue
            seen.add((id(word), xt))
            body = list(word.body)
            while body:
                item = body.pop()
                instruction = item.instruction
                key = xt, self.position(origin[0], item.source)
                if isinstance(instruction, Word):
                    target, compiled = self.trace.calls.get(key, (None, False))
                    if target is not None and not compiled:
                        raise item.source.error(f"Gforth executes {instruction.name!r} at compile time")
                    pending.append((instruction, target))
                elif isinstance(instruction, Literal) and cell_literal(item.source.text) is not None:
                    actual = self.trace.literals.get(key)
                    if actual != instruction.value:
                        observed = "no single-cell literal" if actual is None else str(actual)
                        raise item.source.error(f"literal {item.source.text!r}: Gforth compiled {observed}, "
                                                f"4thGraph compiled {instruction.value}")
                else:
                    expected = self.trace.builtins.get(item.source.name)
                    if expected is None:
                        raise item.source.error(f"{item.source.text!r} has no shared Gforth implementation")
                    if self.trace.calls.get(key) != expected:
                        raise item.source.error(f"Gforth bound a different primitive for {item.source.text!r}")
                    if isinstance(instruction, Conditional):
                        body.extend(instruction.yes)
                        body.extend(instruction.no)


def load_plan(source, *, forth=None):
    source = Path(source).resolve(strict=True)
    tracer = Path(__file__).with_name("source-trace.fs").resolve()
    with TemporaryDirectory(prefix="4thgraph-gforth-") as temporary:
        trace_file = Path(temporary) / "source.trace"
        vocabulary = "4thgraph-trace-vocabulary " + " ".join(sorted(RULE_BUILTINS))
        result = subprocess.run([forth or os.environ.get("GFORTH", "gforth"), str(tracer), "-e", vocabulary,
                                 str(source), "-e", "bye"],
                                cwd=source.parent, env={**os.environ, "FOURTHGRAPH_SOURCE_TRACE": str(trace_file)},
                                capture_output=True, text=True, check=False)
        if result.returncode:
            raise ValueError(result.stderr.strip() or f"Forth exited with status {result.returncode}")
        with trace_file.open(encoding="utf-8") as records:
            return replace(parse_plan(result.stdout), trace=SourceTrace(records, source.parent))


def lower_serial(plan, rules, keys, current, *, target="both", source_bytes=None):
    """Build locks only for layouts the current serial backend implements completely."""
    if len(plan.roots) != 1 or len(plan.stages) < 2 or plan.conflicts:
        raise CompileError("the Script backend requires a two-or-more-stage serial chain with one root")
    rules = Path(rules)
    source_bytes = rules.read_bytes() if source_bytes is None else source_bytes
    if plan.trace is None:
        raise CompileError("lock generation requires the relation bindings from load_plan")
    frontend = BoundRules(source_bytes.decode("utf-8"), rules.resolve(), plan.trace)
    stages, previous = [], plan.roots
    root = Token(f"resource-{previous[0]}", 1, 1, "Forth network plan")
    flags = plan.stages[0].sighashes
    if flags not in SERIAL_MODES:
        raise CompileError("the serial Script backend requires ForkID ALL or Chronicle OTDA ALL")
    for index, record in enumerate(plan.stages, 1):
        final = index == len(plan.stages)
        if record.policy != "direct-script":
            raise CompileError(f"{record.name}: the serial Script backend cannot enforce {record.policy}")
        if record.amount != "none" or record.sighashes != flags:
            raise CompileError(f"{record.name}: unsupported prevout amount evidence or different sighash policy")
        count = 2 if final else 1
        if (record.consumes != previous or len(record.produces) != count or
                record.input_selection != Selection("ordered", 1, 1) or
                record.output_selection != Selection("ordered", count, count)):
            raise CompileError(f"{record.name}: the serial Script backend needs exact ordered input and output counts")
        word = frontend.words.get(record.relation)
        if word is None or (word.takes, word.gives) != (("u32",), ("route" if final else "u32",)):
            raise CompileError(f"{record.name}: invalid or missing relation word {record.relation!r}")
        frontend.check_word(word, plan.trace.bindings.get(record.name))
        require_script(word)
        at = Token(record.name, index + 1, 1, "Forth network plan")
        source = Token(f"resource-{record.consumes[0]}", at.line, at.column, at.module)
        result = Token(f"resource-{record.produces[0]}", at.line, at.column, at.module)
        stages.append(Stage(record.name, word, source, result, record.owner, at))
        previous = record.produces
    workflow = Workflow(root, tuple(stages), libraries=frontend.library_imports)
    return WorkflowContracts(workflow, keys, current, mode="serial", target=target,
                             sighash_family=SERIAL_MODES[flags])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--keys", type=Path)
    parser.add_argument("--current", type=int)
    parser.add_argument("--target", default="both", choices=TARGETS)
    args = parser.parse_args()
    contract_options = (args.rules, args.keys, args.current)
    if any(option is not None for option in contract_options) and None in contract_options:
        parser.error("--rules, --keys and --current must be provided together")
    try:
        plan = load_plan(args.source)
        result = {"plan": plan.describe(), "locks": None}
        if args.rules is not None:
            keys = {role: bytes.fromhex(key) for role, key in json.loads(args.keys.read_text()).items()}
            source_bytes = args.rules.read_bytes()
            contract = lower_serial(plan, args.rules, keys, args.current, target=args.target, source_bytes=source_bytes)
            result["locks"] = contract.artifact(source_bytes)
        print(json.dumps(result, sort_keys=True, indent=2))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

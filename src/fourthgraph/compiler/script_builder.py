"""Compile Forth words that construct Bitcoin Script at build or instantiation time."""

from pathlib import Path

from fourthgraph.bsv.script import OPS, number, push

from .source import CompileError, Located, SourceCompiler, Word, evaluate
from .script_formula import read_formula, validate_formula_passes
from fourthgraph.stdlib import WALLET_BACKEND
from .wordsets import script_word


def repeat(code, count):
    if not 0 <= count <= 256:
        raise CompileError("Script repetition must be between 0 and 256")
    return code * count


def build_word(takes, gives, run):
    return script_word(takes, gives, None, run, build_only=True)


def emit_opcode(opcode):
    return build_word("script", "script", lambda code: code + bytes([opcode]))


SCRIPT_WORDS = {
    name.lower().replace("_", "-"): emit_opcode(opcode)
    for name, opcode in OPS.items()
} | {
    "bsv-empty": build_word("", "script", bytes),
    "bsv-push": build_word("script bytes", "script", lambda code, data: code + push(data)),
    "bsv-num": build_word("script cell", "script", lambda code, value: code + number(value)),
    "bsv-num-be": build_word("script bytes", "script",
                             lambda code, data: code + number(int.from_bytes(data, "big"))),
    "bsv-cat-code": build_word("script script", "script", bytes.__add__),
    "bsv-repeat-code": build_word("script cell", "script", repeat),
    "script>bytes": build_word("script", "bytes", bytes),
    "script-size": build_word("script", "cell", len),
    "cell>byte": build_word("cell", "bytes", lambda value: value.to_bytes(1, "big")),
}


class ScriptBuilder(SourceCompiler):
    def __init__(self, source, *, source_path=None, vocabulary=None, optimize=False, formula_passes=None,
                 experimental_rules=(), trace_formulas=False):
        if optimize and formula_passes is not None:
            raise ValueError("choose automatic formula optimization or explicit passes")
        self.optimize = optimize
        self.formula_passes = None if formula_passes is None else validate_formula_passes(formula_passes)
        if experimental_rules and formula_passes is None:
            raise ValueError("ordered rules require an explicit terminal pass plan")
        self.experimental_rules = tuple(experimental_rules)
        self.formula_snapshots = {} if trace_formulas else None
        self.formula_stack_plans = {} if trace_formulas else None
        self.formulas = {}
        self.formula_ir = {}
        super().__init__(source, vocabulary=SCRIPT_WORDS | (vocabulary or {}), backend=WALLET_BACKEND,
                         source_path=source_path)

    @classmethod
    def from_file(cls, path, **options):
        path = Path(path)
        return cls(path.read_text(encoding="utf-8"), source_path=path, **options)

    def declaration(self, token):
        if token.name != "formula:":
            super().declaration(token)
            return
        name, formula = read_formula(self.tokens, token, self.ranges)
        if name.name.startswith("bsv-") or name.name in self.words:
            raise name.error(f"invalid or duplicate formula name {name.text!r}")
        diagnostics = []
        if self.experimental_rules or self.formula_snapshots is not None:
            from .formula_experiment import snapshot, transform, validate_rules
            states = [snapshot(formula)] if self.formula_snapshots is not None else None
            for rule in validate_rules(self.experimental_rules):
                formula = transform(formula, rule, diagnostics=diagnostics)
                if states is not None:
                    states.append(snapshot(formula))
            if states is not None:
                self.formula_snapshots[name.name] = states
        plan = {} if self.formula_stack_plans is not None else None
        code, report = formula.lower(optimize=self.optimize, passes=self.formula_passes, trace=plan)
        if diagnostics:
            report["ordered_rules"] = diagnostics
        if plan is not None:
            self.formula_stack_plans[name.name] = plan
        append = build_word("script", "script", lambda prefix: prefix + code)
        self.words[name.name] = Word(("script",), ("script",), (Located(append, name),), "build", name=name.name)
        self.definitions[name.name] = name
        self.formulas[name.name] = report
        self.formula_ir[name.name] = formula

    def emit(self, entry, *args, build_call=None):
        word = self.words.get(entry.casefold())
        if not isinstance(word, Word) or word.gives != ("script",):
            raise CompileError(f"{entry} must produce one Script")
        result, = evaluate(word, *args, build_call=build_call)
        return result

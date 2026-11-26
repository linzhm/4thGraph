"""Compile Forth words that construct Bitcoin Script at build or instantiation time."""

from pathlib import Path

from fourthgraph.bsv.script import OPS, number, push

from .source import CompileError, Located, SourceCompiler, Word, evaluate
from .script_formula import read_formula
from fourthgraph.stdlib import WALLET_BACKEND
from .wordsets import script_word


def repeat(code, count):
    if not 0 <= count <= 256:
        raise CompileError("Script repetition must be between 0 and 256")
    return code * count


def emit_opcode(opcode):
    return script_word("script", "script", b"", lambda code: code + bytes([opcode]))


SCRIPT_WORDS = {
    name.lower().replace("_", "-"): emit_opcode(opcode)
    for name, opcode in OPS.items()
} | {
    "bsv-empty": script_word("", "script", b"", bytes),
    "bsv-push": script_word("script bytes", "script", b"", lambda code, data: code + push(data)),
    "bsv-num": script_word("script cell", "script", b"", lambda code, value: code + number(value)),
    "bsv-num-be": script_word("script bytes", "script", b"",
                              lambda code, data: code + number(int.from_bytes(data, "big"))),
    "bsv-cat-code": script_word("script script", "script", b"", bytes.__add__),
    "bsv-repeat-code": script_word("script cell", "script", b"", repeat),
    "script>bytes": script_word("script", "bytes", b"", bytes),
    "script-size": script_word("script", "cell", b"", len),
    "cell>byte": script_word("cell", "bytes", b"", lambda value: value.to_bytes(1, "big")),
}


class ScriptBuilder(SourceCompiler):
    def __init__(self, source, *, source_path=None, vocabulary=None, optimize=False):
        self.optimize = optimize
        self.formulas = {}
        self.formula_ir = {}
        super().__init__(source, vocabulary=SCRIPT_WORDS | (vocabulary or {}), backend=WALLET_BACKEND,
                         source_path=source_path)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        return cls(path.read_text(encoding="utf-8"), source_path=path)

    def declaration(self, token):
        if token.name != "formula:":
            super().declaration(token)
            return
        name, formula = read_formula(self.tokens, token, self.ranges)
        if name.name.startswith("bsv-") or name.name in self.words:
            raise name.error(f"invalid or duplicate formula name {name.text!r}")
        code, report = formula.lower(optimize=self.optimize)
        append = script_word("script", "script", b"", lambda prefix: prefix + code)
        self.words[name.name] = Word(("script",), ("script",), (Located(append, name),), "build", name=name.name)
        self.definitions[name.name] = name
        self.formulas[name.name] = report
        self.formula_ir[name.name] = formula

    def emit(self, entry, *args):
        word = self.words.get(entry.casefold())
        if not isinstance(word, Word) or word.gives != ("script",):
            raise CompileError(f"{entry} must produce one Script")
        result, = evaluate(word, *args)
        return result

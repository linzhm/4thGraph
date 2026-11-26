"""Compile Forth words that construct Bitcoin Script at build or instantiation time."""

from pathlib import Path

from fourthgraph.bsv.script import OPS, number, push

from .source import CompileError, SourceCompiler, Word, evaluate
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
    def __init__(self, source, *, source_path=None):
        super().__init__(source, vocabulary=SCRIPT_WORDS, backend=WALLET_BACKEND, source_path=source_path)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        return cls(path.read_text(encoding="utf-8"), source_path=path)

    def emit(self, entry, *args):
        word = self.words.get(entry.casefold())
        if not isinstance(word, Word) or word.gives != ("script",):
            raise CompileError(f"{entry} must produce one Script")
        result, = evaluate(word, *args)
        return result

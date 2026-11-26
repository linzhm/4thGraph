"""Lower the committed-key reconstruction word with 4thGraph's native BSV vocabulary."""
from functools import cache
from pathlib import Path

from fourthgraph.bsv.script import asm
from fourthgraph.compiler.source import SourceCompiler, lower
from fourthgraph.compiler.wordsets import Literal, Primitive

SOURCE = Path(__file__).with_name("committed-verifier.fth")


def runtime_word(takes, gives, opcodes):
    def run(*_):
        raise ValueError("this word requires the Bitcoin Script runtime")

    return Primitive(tuple(takes.split()), tuple(gives.split()), asm(opcodes), run,
                     "Script runtime", may_fail=True)


# These local words cover the instructions outside #68's public vocabulary.
# The source order preserves any entries that the caller left on altstack.
SCRIPT_WORDS = {
    "empty-bytes": Literal("bytes", b""),
    "save-bytes": runtime_word("bytes", "", "OP_TOALTSTACK"),
    "restore-bytes": runtime_word("", "bytes", "OP_FROMALTSTACK"),
    "bytes-and": runtime_word("bytes bytes", "bytes", "OP_AND"),
    "copy-digest-byte": runtime_word("bytes bytes bytes bytes", "bytes bytes bytes bytes bytes",
                                     "OP_3 OP_PICK"),
    "swap-if": runtime_word("bytes bytes cell", "bytes bytes", "OP_IF OP_SWAP OP_ENDIF"),
}


@cache
def committed_verifier_parts():
    compiler = SourceCompiler(SOURCE.read_text(encoding="ascii"), vocabulary=SCRIPT_WORDS, source_path=SOURCE)
    start = lower(compiler.words["start-commitment"])
    one_byte = lower(compiler.words["committed-byte"])
    finish = lower(compiler.words["finish-commitment"])
    return start, one_byte, finish


@cache
def committed_verifier_code():
    start, one_byte, finish = committed_verifier_parts()
    return start + one_byte * 32 + finish

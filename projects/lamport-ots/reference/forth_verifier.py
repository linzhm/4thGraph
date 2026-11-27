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
    "swap-if-clear": runtime_word("bytes bytes cell", "bytes bytes", "OP_NOTIF OP_SWAP OP_ENDIF"),
}


@cache
def _compiler():
    return SourceCompiler(SOURCE.read_text(encoding="ascii"), vocabulary=SCRIPT_WORDS, source_path=SOURCE)


@cache
def committed_verifier_parts(*, packed=False):
    compiler = _compiler()
    start = lower(compiler.words["start-commitment"])
    one_byte = lower(compiler.words["packed-byte" if packed else "committed-byte"])
    finish = lower(compiler.words["finish-commitment"])
    return start, one_byte, finish


@cache
def committed_verifier_code():
    start, one_byte, finish = committed_verifier_parts()
    return start + one_byte * 32 + finish


@cache
def subset_verifier_parts():
    from subset import MASK_TABLE

    source = SOURCE.with_name('subset-verifier.fth')
    words = {
        **SCRIPT_WORDS,
        'subset-mask-table': Literal('bytes', MASK_TABLE),
        'digest-offset': runtime_word('bytes', 'cell', '0x00 OP_CAT OP_BIN2NUM OP_DUP OP_ADD'),
        'copy-third': runtime_word('bytes bytes bytes', 'bytes bytes bytes bytes', 'OP_2 OP_PICK'),
        'copy-fourth': runtime_word('bytes bytes bytes cell', 'bytes bytes bytes cell bytes', 'OP_3 OP_PICK'),
        'hash-if': runtime_word('bytes cell', 'bytes', 'OP_IF OP_SHA256 OP_ENDIF'),
    }
    compiler = SourceCompiler(source.read_text(encoding='ascii'), vocabulary=words, source_path=source)
    return tuple(lower(compiler.words[name]) for name in ('start-subset', 'subset-byte', 'finish-subset'))

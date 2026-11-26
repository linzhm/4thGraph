"""Evaluate the native payment project's Forth locking-script constructors."""

from functools import cache
from importlib import import_module
from pathlib import Path

from .script import is_compressed_public_key


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "projects/4thgraph/examples"


@cache
def _constructor(template):
    compiler = import_module("projects.4thgraph.compiler")
    source = SOURCE_DIRECTORY / f"{template}.fth"
    return compiler.evaluate, compiler.SourceCompiler(source.read_text(encoding="utf-8"), source_path=source).words[template]


def _lock(template, recipient):
    evaluate, word = _constructor(template)
    lock, = evaluate(word, recipient)
    return lock


def p2pk_lock(public_key):
    if not is_compressed_public_key(public_key):
        raise ValueError("expected a compressed secp256k1 public key")
    return _lock("p2pk", public_key)


def p2pkh_lock(owner):
    if not isinstance(owner, (bytes, bytearray)) or len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    return _lock("p2pkh", bytes(owner))

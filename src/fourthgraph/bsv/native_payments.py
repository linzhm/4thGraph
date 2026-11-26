"""Evaluate the bundled Forth locking-script constructors."""

from functools import cache

from fourthgraph.bsv.script import is_compressed_public_key


@cache
def _constructor(template):
    from fourthgraph.compiler.source import SourceCompiler, evaluate

    source = f"REQUIRE stdlib/{template}.fth\n"
    return evaluate, SourceCompiler(source).words[f"{template}-lock"]


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

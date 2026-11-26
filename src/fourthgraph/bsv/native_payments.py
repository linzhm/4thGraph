"""Compile the bundled Forth spending conditions."""

from fourthgraph.bsv.script import is_compressed_public_key


def _lock(template, parameter, recipient):
    from fourthgraph.compiler.source import SourceCompiler, lower
    from fourthgraph.stdlib import read_library

    source = read_library(f"std/native-{template}").decode("utf-8")
    frontend = SourceCompiler(source, bindings={parameter: recipient})
    return lower(frontend.words[template])


def p2pk_lock(public_key):
    if not is_compressed_public_key(public_key):
        raise ValueError("expected a compressed secp256k1 public key")
    return _lock("p2pk", "owner-key", public_key)


def p2pkh_lock(owner):
    if not isinstance(owner, (bytes, bytearray)) or len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    return _lock("p2pkh", "owner-hash", bytes(owner))

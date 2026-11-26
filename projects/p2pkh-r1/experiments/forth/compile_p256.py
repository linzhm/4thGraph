"""Compile the experimental P-256 Forth kernels with the 4thGraph front end."""

import argparse
from hashlib import sha256
import json
from operator import add, mul, sub
from pathlib import Path

import compiler
from lowering import compile_word
from shared.script import asm, number
from wordsets import script_word

VERSION = "0.1.0-alpha.1"
SOURCE = Path(__file__).with_name("p256.fth")
ENTRIES = {"p256-add": ("ADD_POINTS", 6), "p256-double": ("DOUBLE_POINT", 3)}
INTEGER = "script-int"


def signed_remainder(value, modulus):
    magnitude = abs(value) % abs(modulus)
    return -magnitude if value < 0 else magnitude


def access_word(depth, *, move):
    takes = (INTEGER,) * (depth + 1)
    gives = takes if move else (*takes, INTEGER)
    code = number(depth) + asm("OP_ROLL" if move else "OP_PICK")

    def run(*values):
        tail = values[1:] if move else values
        return (*tail, values[0])

    return compiler.Primitive(takes, gives, code, run, "static Script stack depth")


class CurveSource(compiler.SourceCompiler):
    def declaration(self, token):
        if not self.words:
            self.words.update({
                "cell>int": script_word("cell", INTEGER, b"", int),
                "int+": script_word(f"{INTEGER} {INTEGER}", INTEGER, asm("OP_ADD"), add),
                "int-": script_word(f"{INTEGER} {INTEGER}", INTEGER, asm("OP_SUB"), sub),
                "int*": script_word(f"{INTEGER} {INTEGER}", INTEGER, asm("OP_MUL"), mul),
                "int-rem": script_word(f"{INTEGER} {INTEGER}", INTEGER, asm("OP_MOD"), signed_remainder),
                "int-nonzero?": script_word(INTEGER, "cell", asm("OP_0NOTEQUAL OP_NEGATE"),
                                            lambda value: -int(value != 0)),
            })
            for depth in range(2, 12):
                self.words[f"int-pick-{depth}"] = access_word(depth, move=False)
                self.words[f"int-roll-{depth}"] = access_word(depth, move=True)
        super().declaration(token)


def build(source):
    previous_types = compiler.TYPES
    compiler.TYPES = previous_types | {INTEGER}
    try:
        words = CurveSource(source.decode()).words
    finally:
        compiler.TYPES = previous_types
    kernels = {}
    for entry, (_, arity) in ENTRIES.items():
        word = words.get(entry)
        if (word is None or word.takes != (INTEGER,) * (arity + 2)
                or word.gives != (INTEGER,) * 5):
            raise compiler.CompileError(f"{entry} must take {arity + 2} Script numbers and return five")
        kernels[entry] = compile_word(word).script
    return kernels


def identity(source):
    return {
        "experiment_version": VERSION,
        "compiler_version": compiler.PROJECT_VERSION,
        "source_sha256": sha256(source).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    source = args.source.read_bytes()
    print(json.dumps({
        **identity(source),
        "kernels": {name: {"bytes": len(code), "sha256": sha256(code).hexdigest(), "hex": code.hex()}
                    for name, code in build(source).items()},
    }, indent=2))


if __name__ == "__main__":
    main()

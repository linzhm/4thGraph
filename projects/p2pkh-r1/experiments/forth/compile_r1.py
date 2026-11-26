"""Build a complete R1 lock by evaluating Forth Script-construction words."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.compiler.source import CompileError, SourceCompiler, evaluate
from fourthgraph.bsv.script import OPS, number, push
from fourthgraph.compiler.wordsets import script_word

VERSION = "0.3.0"
BASELINE_VERSION = "0.2.0"
SOURCE = Path(__file__).with_name("r1.fth")


def repeat(fragment, count):
    if not 0 <= count <= 256:
        raise CompileError("Script repetition must be between 0 and 256")
    return fragment * count


def opcode_word(opcode):
    return script_word("script", "script", b"", lambda code: code + bytes([opcode]))


class R1Source(SourceCompiler):
    def __init__(self, source, owner, *, optimize):
        self.owner = owner
        self.optimize = optimize
        super().__init__(source)

    def declaration(self, token):
        if not self.words:
            self.words.update({name.casefold().replace("_", "-"): opcode_word(opcode)
                               for name, opcode in OPS.items()})
            self.words.update({
                "bsv-empty": script_word("", "script", b"", bytes),
                "bsv-push": script_word("script bytes", "script", b"", lambda code, data: code + push(data)),
                "bsv-num": script_word("script cell", "script", b"", lambda code, value: code + number(value)),
                "bsv-num-be": script_word("script bytes", "script", b"",
                                          lambda code, data: code + number(int.from_bytes(data, "big"))),
                "bsv-cat-code": script_word("script script", "script", b"", bytes.__add__),
                "bsv-repeat-code": script_word("script cell", "script", b"", repeat),
                "bsv-owner": script_word("", "bytes", b"", lambda: self.owner),
                "bsv-optimize?": script_word("", "cell", b"", lambda: -int(self.optimize)),
            })
        super().declaration(token)

    def emit(self, entry):
        word = self.words.get(entry)
        if word is None or (word.takes, word.gives) != (("script",), ("script",)):
            raise CompileError(f"{entry} must have effect script -- script")
        result, = evaluate(word, b"")
        return result


def compile_source(source, owner, *, optimize=False):
    if len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    return R1Source(source.decode(), owner, optimize=optimize)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--owner-hash160", type=bytes.fromhex, default=bytes(20))
    parser.add_argument("--optimize", action="store_true")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    source = args.source.read_bytes()
    lock = compile_source(source, args.owner_hash160, optimize=args.optimize).emit("r1-lock")
    print(json.dumps({
        "experiment_version": VERSION, "baseline_version": BASELINE_VERSION,
        "lock_version": VERSION if args.optimize else BASELINE_VERSION,
        "source_sha256": sha256(source).hexdigest(), "optimized": args.optimize,
        "lock_bytes": len(lock), "lock_sha256": sha256(lock).hexdigest(), "lock_hex": lock.hex(),
    }, indent=2))


if __name__ == "__main__":
    main()

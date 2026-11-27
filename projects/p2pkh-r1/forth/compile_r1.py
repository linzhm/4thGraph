"""Build a complete R1 lock by evaluating Forth Script-construction words."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.compiler.script_builder import ScriptBuilder, build_word

VERSION = "0.4.0"
BASELINE_VERSION = "0.2.0"
SOURCE = Path(__file__).with_name("r1.fth")


def compile_source(source, owner, *, optimize=False, source_path=SOURCE):
    if len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    return ScriptBuilder(source.decode(), source_path=source_path, optimize=optimize,
                         vocabulary={"bsv-owner": build_word("", "bytes", lambda: owner)})


def previous_build(owner, *, optimize):
    return ScriptBuilder("REQUIRE stdlib/wallet/r1.fth", vocabulary={
        "bsv-owner": build_word("", "bytes", lambda: owner),
        "bsv-optimize?": build_word("", "cell", lambda: -int(optimize)),
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--owner-hash160", type=bytes.fromhex, default=bytes(20))
    parser.add_argument("--optimize", action="store_true")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    source = args.source.read_bytes()
    compiler = compile_source(source, args.owner_hash160, optimize=args.optimize, source_path=args.source)
    lock = compiler.emit("r1-lock", b"")
    print(json.dumps({
        "experiment_version": VERSION, "baseline_version": BASELINE_VERSION,
        "lock_version": VERSION, "formulas": compiler.formulas,
        "source_sha256": sha256(source).hexdigest(), "optimized": args.optimize,
        "lock_bytes": len(lock), "lock_sha256": sha256(lock).hexdigest(), "lock_hex": lock.hex(),
    }, indent=2))


if __name__ == "__main__":
    main()

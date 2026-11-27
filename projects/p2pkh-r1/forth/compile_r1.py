"""Build a complete R1 lock by evaluating Forth Script-construction words."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.compiler.script_builder import ScriptBuilder, build_word

VERSION = "0.4.0"
BASELINE_VERSION = "0.2.0"
SOURCE = Path(__file__).with_name("r1.fth")
PAYMENT_ENTRY = "r1-baseline-lock"
COUNTER_ENTRY = "r1-baseline-counter"
ENTRY_SOURCES = {
    "r1-lock": SOURCE,
    PAYMENT_ENTRY: SOURCE.with_name("r1-baseline.fth"),
    COUNTER_ENTRY: SOURCE.with_name("r1-baseline-counter.fth"),
}


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


def emit_lock(compiler, entry, counter_state=None):
    if entry == COUNTER_ENTRY:
        if type(counter_state) is not int or not 0 <= counter_state < 2**32:
            raise ValueError("the counter entry requires an unsigned 32-bit --counter-state")
        return compiler.emit(entry, b"", counter_state.to_bytes(5, "little"))
    if counter_state is not None:
        raise ValueError("--counter-state is only supported by the counter entry")
    return compiler.emit(entry, b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--entry", choices=ENTRY_SOURCES, default="r1-lock")
    parser.add_argument("--counter-state", type=int, help="initial u32 state for r1-baseline-counter")
    parser.add_argument("--owner-hash160", type=bytes.fromhex, default=bytes(20))
    parser.add_argument("--optimize", action="store_true")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    source_path = args.source or ENTRY_SOURCES[args.entry]
    source = source_path.read_bytes()
    try:
        compiler = compile_source(source, args.owner_hash160, optimize=args.optimize, source_path=source_path)
        lock = emit_lock(compiler, args.entry, args.counter_state)
    except ValueError as error:
        parser.error(str(error))
    identity = ({"experiment_version": VERSION, "baseline_version": BASELINE_VERSION, "lock_version": VERSION}
                if args.entry == "r1-lock" else {"entry": args.entry, "counter_state": args.counter_state,
                                                 "dependencies": {item.name: item.sha256
                                                                  for item in compiler.library_imports}})
    print(json.dumps({
        **identity, "formulas": compiler.formulas,
        "source_sha256": sha256(source).hexdigest(), "optimized": args.optimize,
        "lock_bytes": len(lock), "lock_sha256": sha256(lock).hexdigest(), "lock_hex": lock.hex(),
    }, indent=2))


if __name__ == "__main__":
    main()

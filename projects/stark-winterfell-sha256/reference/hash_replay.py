"""Check the SHA-256 profile's Forth primitives on the local and regtest engines."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from fourthgraph.benchmark.validation import Node, chain_metadata, chain_verdict
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.source import SourceCompiler

PROJECT = Path(__file__).resolve().parents[1]


def cases(name, inputs):
    altered = bytes([inputs[0][0] ^ 1]) + inputs[0][1:]
    yield "changed_first_byte", [altered, *inputs[1:]]
    if name in {"trace-row", "merkle-parent", "seed-counter"}:
        yield "short_first_item", [inputs[0][:-1], *inputs[1:]]
    if len(inputs) == 2:
        yield "short_second_item", [inputs[0], inputs[1][:-1]]
    if name == "merkle-parent":
        yield "reversed_children", list(reversed(inputs))
    if name == "seed-counter":
        yield "reversed_counter_bytes", [inputs[0], inputs[1][::-1]]


def evaluate_lock(lock, inputs):
    try:
        stack, alt = evaluate(lock, inputs)
    except ScriptError:
        return False
    return stack == [b"\x01"] and not alt


def replay(node):
    source = PROJECT / "hashes.fth"
    frontend = SourceCompiler(source.read_text(), source_path=source)
    rows = []
    for line in (PROJECT / "versions/v0.1.0/hash-vectors.txt").read_text().splitlines():
        name, *arguments, expected = line.split()
        inputs = [bytes.fromhex(argument) for argument in arguments]
        word = frontend.words[f"stark-sha256-{name}"]
        script = compile_word(word, "stack", spend_entry=True).script
        lock = script + push(bytes.fromhex(expected)) + asm("OP_EQUAL")
        parent = Transaction(
            (Input(sha256(name.encode()).digest(), 0),),
            (Output(1000, lock),),
        )
        rejected = []
        for scenario, stack in [("valid", inputs), *cases(name, inputs)]:
            accepted = scenario == "valid"
            if evaluate_lock(lock, stack) != accepted:
                raise ValueError(f"Script evaluator disagrees on {name}/{scenario}")
            if node:
                tx = Transaction(
                    (Input(parent.txid_wire(), 0, b"".join(map(push, stack))),),
                    (Output(900, number(1)),),
                )
                if node.verdicts(tx, (parent,)) != [accepted] or chain_verdict(tx, (parent,)) != accepted:
                    raise ValueError(f"independent Script engine disagrees on {name}/{scenario}")
            if not accepted:
                rejected.append(scenario)
        rows.append({
            "name": name,
            "script_bytes": len(script),
            "script_sha256": sha256(script).hexdigest(),
            "rejections": rejected,
        })
    result = {
        "schema_version": 1,
        "scope": "SHA-256 primitives with synthetic previous outputs",
        "engines": ["development evaluator", "BSV Node", "chain-gang"] if node else ["development evaluator"],
        "vectors": rows,
    }
    if node:
        result["native"] = {"bsv_node_version": node.version, "chain_gang": chain_metadata()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="require both regtest verification engines")
    parser.add_argument("--check", action="store_true", help="check the pinned Script digests and vectors")
    parser.add_argument("--output", type=Path, default=PROJECT / "workspace/build/hash-checks.json")
    args = parser.parse_args()
    try:
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"]) if args.native else None
        result = replay(node)
        if args.check:
            expected = json.loads((PROJECT / "versions/v0.1.0/hash-checks.json").read_text())
            if result["vectors"] != expected["vectors"]:
                raise ValueError("hash replay differs from the selected v0.1.0 Script record")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    except (KeyError, OSError, ValueError) as error:
        parser.error(str(error))
    print(args.output)


if __name__ == "__main__":
    main()

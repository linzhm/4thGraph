"""Replay real Winterfell trace openings using the compiled Merkle verification lock."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from fourthgraph.benchmark.validation import chain_verdict
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import encode_num, number, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.source import SourceCompiler

from native_replay import native_engines

PROJECT = Path(__file__).resolve().parents[1]
RELEASE = PROJECT / "versions/v0.2.0"
SOURCE = PROJECT / "opening.fth"


def flip_first(data):
    return bytes([data[0] ^ 1]) + data[1:]


def mutations(row, path, index):
    yield "wrong_row", [flip_first(row), path, encode_num(index)]
    yield "wrong_sibling", [row, flip_first(path), encode_num(index)]
    yield "reordered_siblings", [row, path[32:64] + path[:32] + path[64:], encode_num(index)]
    yield "short_path", [row, path[:-1], encode_num(index)]
    yield "extra_path_byte", [row, path + b"\0", encode_num(index)]
    yield "wrong_index", [row, path, encode_num(index ^ 1)]
    yield "out_of_range_index", [row, path, encode_num(8192)]
    yield "negative_index", [row, path, encode_num(-1)]
    yield "noncanonical_index", [row, path, encode_num(index) + b"\0"]


def script_verdict(lock, stack, observe=None):
    try:
        main, alt = evaluate(lock, stack, observe_stack=observe)
    except ScriptError:
        return False
    return main == [b"\x01"] and not alt


def replay(binary, scratch, node):
    cases = json.loads((RELEASE / "opening-cases.json").read_text())
    proofs = {
        (row["current"], row["next"]): row["proof_sha256"]
        for row in json.loads((PROJECT / "versions/v0.1.0/measurements.json").read_text())["statements"]
    }
    records = []
    for case in cases:
        current, next_state, query = case["current"], case["next"], case["query"]
        proof = scratch / "counter.proof"
        result = subprocess.check_output([binary, "prove", str(current), proof], text=True)
        proof_digest = sha256(proof.read_bytes()).hexdigest()
        if int(result) != next_state or proof_digest != proofs[current, next_state]:
            raise ValueError(f"proof bytes disagree with v0.1.0 for {current}")

        opening = json.loads(subprocess.check_output(
            [binary, "trace-opening", str(current), str(next_state), str(query), proof]
        ))
        index = opening["index"]
        root, row, path = (bytes.fromhex(opening[name]) for name in ("root", "row", "path"))
        frontend = SourceCompiler(SOURCE.read_text(), source_path=SOURCE, bindings={"trace-root": root})
        word = frontend.words["verify-trace-opening"]
        lock = compile_word(word, "stack", spend_entry=True).script
        valid = [row, path, encode_num(index)]
        peak = 0

        def observe(main, alt):
            nonlocal peak
            peak = max(peak, sum(map(len, main)) + sum(map(len, alt)))

        parent = Transaction(
            (Input(bytes.fromhex(proof_digest), query),),
            (Output(1000, lock),),
        )
        rejected = []
        for scenario, stack in [("valid", valid), *mutations(row, path, index)]:
            accepted = scenario == "valid"
            if script_verdict(lock, stack, observe if accepted else None) != accepted:
                raise ValueError(f"Script evaluator disagrees on query {query}/{scenario}")
            if node:
                tx = Transaction(
                    (Input(parent.txid_wire(), 0, b"".join(map(push, stack))),),
                    (Output(900, number(1)),),
                )
                if node.verdicts(tx, (parent,)) != [accepted] or chain_verdict(tx, (parent,)) != accepted:
                    raise ValueError(f"native Script engine disagrees on query {query}/{scenario}")
            if not accepted:
                rejected.append(scenario)
        records.append({
            **case,
            "index": index,
            "trace_root": root.hex(),
            "proof_sha256": proof_digest,
            "lock_bytes": len(lock),
            "lock_sha256": sha256(lock).hexdigest(),
            "path_bytes": len(path),
            "unlock_bytes": sum(len(push(item)) for item in valid),
            "stack_payload_peak_bytes": peak,
            "rejections": rejected,
        })
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--native", action="store_true", help="require both regtest engines")
    parser.add_argument("--check", action="store_true", help="check the pinned opening record")
    parser.add_argument("--output", type=Path, default=PROJECT / "workspace/build/opening-replay.json")
    args = parser.parse_args()
    try:
        node, native = native_engines() if args.native else (None, None)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=args.output.parent) as scratch:
            records = replay(args.binary.resolve(), Path(scratch), node)
        if args.check and records != json.loads((RELEASE / "opening-checks.json").read_text())["openings"]:
            raise ValueError("opening replay differs from the selected v0.2.0 record")
        report = {"schema_version": 1, "openings": records}
        if native is not None:
            report["native"] = native
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(args.output)


if __name__ == "__main__":
    main()

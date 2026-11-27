"""Compare the public STARK statements with 4thGraph's Forth and Script evaluators."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from fourthgraph.bsv.evaluate import evaluate as evaluate_script
from fourthgraph.bsv.script import decode_num, encode_num
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.source import SourceCompiler, evaluate

PROJECT = Path(__file__).resolve().parents[1]
RELEASE = PROJECT / "versions/v0.1.0"
WORKSPACE = PROJECT / "workspace"
U32_MASK = (1 << 32) - 1


def digest(data):
    return sha256(data).hexdigest()


def verify(binary, current, result, proof, *, accepted):
    status = subprocess.run(
        [binary, "verify", str(current), str(result), proof], text=True, capture_output=True,
    )
    if status.returncode != (0 if accepted else 1):
        raise ValueError(f"unexpected verify status for {current}, {result}, {proof.name}: {status.stderr}")


def replay(binary, directory):
    source = PROJECT / "counter.fth"
    frontend = SourceCompiler(source.read_text(), source_path=source)
    word = frontend.words["counter-block"]
    script = compile_word(word, "stack", spend_entry=True).script
    statements = json.loads((RELEASE / "statements.json").read_text())
    rows = []

    for statement in statements:
        current, result = statement["current"], statement["next"]
        initial_stack = [encode_num(current)]
        stack, alt = evaluate_script(script, initial_stack)
        if evaluate(word, current) != (result,) or len(stack) != 1 or decode_num(stack[0]) != result or alt:
            raise ValueError(f"Forth or Script disagrees with {statement['name']}")

        proof = directory / f"{statement['name']}.proof"
        proved = subprocess.run([binary, "prove", str(current), proof], text=True, capture_output=True)
        if proved.returncode or int(proved.stdout) != result:
            raise ValueError(f"unexpected STARK prover result for {statement['name']}: {proved.stderr}")
        blob = proof.read_bytes()
        verify(binary, current, result, proof, accepted=True)
        shifted_current, shifted_result = (current + 1) & U32_MASK, (result + 1) & U32_MASK
        verify(binary, shifted_current, result, proof, accepted=False)
        verify(binary, current, shifted_result, proof, accepted=False)
        verify(binary, shifted_current, shifted_result, proof, accepted=False)
        rows.append({
            **statement,
            "proof_bytes": len(blob),
            "proof_sha256": digest(blob),
            "statement_rejections": ["wrong_current", "wrong_next", "other_valid_statement"],
        })

    wrap, = (statement for statement in statements if statement["name"] == "wraps-at-end")
    proof = directory / f"{wrap['name']}.proof"
    blob = proof.read_bytes()
    middle = len(blob) // 2
    malformed = {
        "mutated": blob[:middle] + bytes([blob[middle] ^ 1]) + blob[middle + 1:],
        "truncated": blob[:-1],
        "trailing_byte": blob + b"\x00",
    }
    for name, payload in malformed.items():
        probe = directory / f"{name}.proof"
        probe.write_bytes(payload)
        verify(binary, wrap["current"], wrap["next"], probe, accepted=False)
    verify(binary, 1 << 32, wrap["next"], proof, accepted=False)

    return {
        "schema_version": 1,
        "script": {
            "arithmetic_entry_bytes": len(script),
            "sha256": digest(script),
            "source_sha256": digest(source.read_bytes()),
            "imports": {item.name: item.sha256 for item in frontend.library_imports},
        },
        "statements": rows,
        "other_rejections": [*malformed, "out_of_range_current"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="check the pinned proof and Script digests")
    parser.add_argument("--measurements", type=Path, default=RELEASE / "measurements.json",
                        help="expected replay record for the selected proof profile")
    parser.add_argument("--output", type=Path, default=WORKSPACE / "build/replay.json")
    args = parser.parse_args()
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=args.output.parent) as temporary:
            evidence = replay(args.binary.resolve(), Path(temporary))
        if args.check and evidence != json.loads(args.measurements.read_text()):
            raise ValueError(f"replay differs from {args.measurements}")
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(args.output)


if __name__ == "__main__":
    main()

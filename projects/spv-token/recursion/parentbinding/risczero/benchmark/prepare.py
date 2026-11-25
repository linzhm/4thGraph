"""Prepare the same public statement and parent witness for both benchmarks."""

import argparse
import json
from pathlib import Path

from parent_prefix import checkpoint_record
from shared.transaction import hash256
from token_checkpoint_verifier import statement_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    fixture = Path(__file__).with_name("regtest-parent.hex")
    parent = bytes.fromhex(fixture.read_text())
    record = checkpoint_record(parent)
    args.out.mkdir(parents=True, exist_ok=True)

    wire = statement_bytes(bytes.fromhex(record["txid_wire"]), bytes.fromhex(record["midstate"]),
                           bytes.fromhex(record["suffix"]))
    with (args.out / "parent.bin").open("xb") as stream:
        stream.write(parent)
    with (args.out / "digest.txt").open("x") as stream:
        print(hash256(wire).hex(), file=stream)
    with (args.out / "groth16-input.jsonl").open("x") as stream:
        for case in range(1, 4):
            print(json.dumps({"id": str(case), "parent": parent.hex(), "statement": wire.hex(),
                              "out": str((args.out / f"groth16-proof-{case}.json").resolve())}), file=stream)


if __name__ == "__main__":
    main()

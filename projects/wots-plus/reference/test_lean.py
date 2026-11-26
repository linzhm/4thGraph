"""Replay complete WOTS+ inputs against the independent bsv-script-lean CLI."""

import argparse
from dataclasses import replace
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from fixtures import malformed_cases, mode_cases, mode_fixture


def cases(*, compact=False):
    profile = "compact" if compact else False
    _, parents, signed = mode_fixture(0x41, cached_constants=profile)
    yield "genesis_41_paired", signed, parents, 1, True, 1, 2
    yield "genesis_41_locktime", replace(signed, locktime=1), parents, 1, False, 1, 2
    for fixture in mode_cases(cached_constants=profile):
        yield (*fixture, 3, 4)
    for fixture in malformed_cases(cached_constants=profile):
        yield (*fixture, 3, 4)


def check(binary, directory, tx, parents, index, funding_height, spend_height):
    # A file argument avoids the OS per-argument limit for a large scriptPubKey.
    tx_file = directory / "spend.hex"
    tx_file.write_text(tx.serialize().hex(), encoding="ascii")
    prevouts = []
    for tx_input, parent in zip(tx.inputs, parents, strict=True):
        previous = parent.outputs[tx_input.vout]
        prevouts.append({
            "txid": parent.txid(),
            "vout": tx_input.vout,
            "script": previous.script.hex(),
            "satoshis": previous.value,
            "height": funding_height,
        })
    prevouts_file = directory / "prevouts.json"
    prevouts_file.write_text(json.dumps(prevouts), encoding="ascii")
    result = subprocess.check_output([
        str(binary), "eval", "--tx", f"@{tx_file}", "--prevouts", f"@{prevouts_file}",
        "--config", "sv-regtest", "--genesis-height", "1", "--chronicle-height", "3",
        "--spend-height", str(spend_height), "--consensus", "true", "--input", str(index),
    ], text=True)
    return json.loads(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bsvs", type=Path, help="Path to the upstream eval/bsvs wrapper")
    parser.add_argument("--compact", action="store_true", help="Replay the compact template")
    args = parser.parse_args()
    binary = args.bsvs.resolve(strict=True)
    total = 0
    mismatches = 0
    versions = set()
    with TemporaryDirectory(prefix="wots-plus-lean-") as scratch:
        for label, tx, parents, index, valid, funding_height, spend_height in cases(compact=args.compact):
            result = check(binary, Path(scratch), tx, parents, index, funding_height, spend_height)
            verdict = "valid" if valid else "invalid"
            total += 1
            versions.add(result["spec"])
            if result["gate"]["verdict"] != "valid" or result["verdict"] != verdict:
                mismatches += 1
                print(f"{label}: expected {verdict}, got {result['verdict']} ({result['code']})"
                      f" with transaction gate {result['gate']}")
    print(f"{', '.join(sorted(versions))}: {total - mismatches}/{total} WOTS+ cases matched")
    return bool(mismatches)


if __name__ == "__main__":
    raise SystemExit(main())

"""Measure the detached Script Lab and sCrypt Schnorr verifiers on public fixtures."""

import argparse
import csv
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess

from bip340 import lift_x, to_bytes
from schnorr_script import TEMPLATE_DIR, verifier
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata, chain_verdict, timed
from shared.script import push
from shared.transaction import Input, Output, Transaction


def measure(lock, unlock, node, samples):
    # Synthetic detached verifier case. The surrounding transaction supplies
    # execution context and framing, while the script's message is a fixture.
    parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),))
    spend = Transaction((Input(parent.txid_wire(), 0, unlock),), (Output(9_900, b"\x51"),))
    chain_ok, chain_ms = timed(lambda: chain_verdict(spend, (parent,)), samples)
    node_ok, node_ms = timed(lambda: node.verdicts(spend, (parent,))[0], samples)
    result = {
        "verifier_bytes": len(lock),
        "verifier_sha256": sha256(lock).hexdigest(),
        "witness_bytes": len(unlock),
        "combined_script_bytes": len(lock) + len(unlock),
        "chain_gang": chain_ok,
        "bsv_node": node_ok,
    }
    if samples:
        result["median_ms"] = {"chain_gang": chain_ms, "bsv_node_rpc": node_ms}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream_checkout", type=Path)
    parser.add_argument("--compiler-study", action="store_true", help="compile and replay official scryptc -O output")
    parser.add_argument("--samples", type=int, default=0, help="timed replays per engine and verifier")
    args = parser.parse_args()
    if args.samples < 0:
        parser.error("sample count must be nonnegative")
    if chain_metadata()["commit"] != CONTEXT_PIN:
        parser.error("install the pinned chain-gang revision from the project requirements")
    if not os.environ.get("REGTEST_URL") or not os.environ.get("REGTEST_COOKIE"):
        parser.error("run through shared/verify_node.sh")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    probe = Path(__file__).with_name("comparison") / "scrypt_legacy.cjs"
    command = ["node", "--max-old-space-size=8192", str(probe), str(args.upstream_checkout)]
    if args.compiler_study:
        command.append("--compiler-study")
    result = subprocess.run(command, stdout=subprocess.PIPE, check=True)
    upstream = json.loads(result.stdout)
    with (TEMPLATE_DIR / "bip340-vectors.csv").open(newline="", encoding="ascii") as vectors:
        vector = next(csv.DictReader(vectors))
    key, message, signature = (bytes.fromhex(vector[field]) for field in ("public key", "message", "signature"))
    if message.hex() != upstream["message"] or key.hex() != upstream["publicKey"][2:66]:
        raise ValueError("external fixture uses a different message or public x-coordinate")
    key_y = to_bytes(lift_x(key)[1])
    nonce_y = to_bytes(lift_x(signature[:32])[1])
    witness = b"".join(map(push, (message, key, key_y, signature, nonce_y)))
    legacy_witness = bytes.fromhex(upstream["unlock"])
    rows = {
        "scrypt_legacy": measure(bytes.fromhex(upstream["lock"]), legacy_witness, node, args.samples),
        "script_lab_bip340": measure(verifier(), witness, node, args.samples),
    }
    if args.compiler_study:
        rows["scrypt_legacy"]["inline_field_inverses"] = upstream["plainInverse"]
        optimized = measure(bytes.fromhex(upstream["optimizedLock"]), legacy_witness, node, args.samples)
        optimized["inline_field_inverses"] = upstream["optimizedInverse"]
        rows["scrypt_legacy_optimized"] = optimized
    print(json.dumps({
        "scrypt_source": upstream["sourceCommit"],
        "scrypt_compiler_sha256": upstream["compilerSha256"],
        "scrypt_sdk": {"verdict": upstream["sdkVerdict"], "error": upstream["sdkError"]},
        "samples_per_verifier_and_engine": args.samples,
        **rows,
    }, indent=2))
    if not all(row[engine] for row in rows.values() for engine in ("chain_gang", "bsv_node")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

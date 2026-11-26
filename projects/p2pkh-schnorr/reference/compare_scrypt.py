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
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata, chain_verdict
from shared.script import push
from shared.transaction import Input, Output, Transaction


def measure(lock, unlock, node):
    # Synthetic detached verifier case. The surrounding transaction supplies
    # execution context and framing, while the script's message is a fixture.
    parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),))
    spend = Transaction((Input(parent.txid_wire(), 0, unlock),), (Output(9_900, b"\x51"),))
    return {
        "verifier_bytes": len(lock),
        "verifier_sha256": sha256(lock).hexdigest(),
        "witness_bytes": len(unlock),
        "combined_script_bytes": len(lock) + len(unlock),
        "chain_gang": chain_verdict(spend, (parent,)),
        "bsv_node": node.verdicts(spend, (parent,))[0],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream_checkout", type=Path)
    args = parser.parse_args()
    if chain_metadata()["commit"] != CONTEXT_PIN:
        parser.error("install the pinned chain-gang revision from the project requirements")
    if not os.environ.get("REGTEST_URL") or not os.environ.get("REGTEST_COOKIE"):
        parser.error("run through shared/verify_node.sh")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    probe = Path(__file__).with_name("comparison") / "scrypt_legacy.cjs"
    result = subprocess.run(
        ["node", "--max-old-space-size=8192", str(probe), str(args.upstream_checkout)],
        stdout=subprocess.PIPE,
        check=True,
    )
    upstream = json.loads(result.stdout)
    with (TEMPLATE_DIR / "bip340-vectors.csv").open(newline="", encoding="ascii") as vectors:
        vector = next(csv.DictReader(vectors))
    key, message, signature = (bytes.fromhex(vector[field]) for field in ("public key", "message", "signature"))
    if message.hex() != upstream["message"] or key.hex() != upstream["publicKey"][2:66]:
        raise ValueError("external fixture uses a different message or public x-coordinate")
    key_y = to_bytes(lift_x(key)[1])
    nonce_y = to_bytes(lift_x(signature[:32])[1])
    witness = b"".join(map(push, (message, key, key_y, signature, nonce_y)))
    legacy = measure(bytes.fromhex(upstream["lock"]), bytes.fromhex(upstream["unlock"]), node)
    baseline = measure(verifier(), witness, node)
    print(json.dumps({
        "scrypt_source": upstream["sourceCommit"],
        "scrypt_compiler_sha256": upstream["compilerSha256"],
        "scrypt_sdk": {"verdict": upstream["sdkVerdict"], "error": upstream["sdkError"]},
        "scrypt_legacy": legacy,
        "script_lab_bip340": baseline,
    }, indent=2))
    if not all(row[engine] for row in (legacy, baseline) for engine in ("chain_gang", "bsv_node")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

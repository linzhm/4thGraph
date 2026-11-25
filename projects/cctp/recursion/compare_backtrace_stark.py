"""Prove the admitted payment openings with RISC Zero and count wire payloads."""

import argparse
from hashlib import sha256
import json
import lzma
import os
from pathlib import Path
import subprocess
from time import perf_counter

from covenant_backtrace import PROOF_BYTES, PROOF_FIELDS, parent_layout
from run_covenant_backtrace_regtest import save
from shared.script import push
from shared.transaction import Transaction


def run(archive_path, vm, guest, verify, out):
    out.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "RISC0_DEV_MODE"}
    image_id = subprocess.check_output([vm, "--elf", guest, "--id"], env=env, text=True).strip()
    with lzma.open(archive_path, "rt") as stream:
        archive = json.load(stream)
    summary = archive["summary"]
    payments = {}
    for label, snark in summary["payments"].items():
        tx = Transaction.parse(bytes.fromhex(archive["transactions"][snark["txid"]]))
        const = tx.inputs[0].script[PROOF_FIELDS * (PROOF_BYTES + 1):]
        private = out / f"{label}-input.bin"
        witness = bytearray(tx.inputs[0].txid)
        for item in tx.inputs[1:]:
            raw = bytes.fromhex(archive["transactions"][item.txid[::-1].hex()])
            if Transaction.parse(raw).txid_wire() != item.txid:
                raise ValueError("archive parent bytes do not match the payment's actual outpoint")
            witness.extend(bytes([parent_layout(raw)]) + item.vout.to_bytes(4, "little") + raw)
        private.write_bytes(witness)
        row = {}
        for kind in ("composite", "succinct"):
            receipt = out / f"{label}-{kind}.bin"
            start = perf_counter()
            subprocess.run([vm, "--elf", guest, "--initial-input", private, "--receipt-kind", kind,
                            "--receipt", receipt], check=True, env=env)
            wall = perf_counter() - start
            status = subprocess.check_output([verify, receipt, image_id, snark["statement_digest"]],
                                             text=True, env=env)
            check = dict(field.split("=") for field in status.split())
            if check["kind"] != kind:
                raise ValueError("unexpected STARK receipt type")
            encoded = receipt.read_bytes()
            candidate = tx.with_script(0, push(encoded) + const)
            row[kind] = {
                "prove_process_seconds": wall, "native_verify_seconds": float(check["native_verify_seconds"]),
                "receipt_bytes": len(encoded), "receipt_sha256": sha256(encoded).hexdigest(),
                "payment_bytes_with_raw_receipt_substituted": len(candidate.serialize()),
            }
            print(label, kind, f"{wall:.2f}s", len(encoded), flush=True)
        payments[label] = row
    return {"scope": "Actual identical opening statement and BSV parents. Wire substitution excludes the STARK verifier "
                     "and its funding. These substitutions have not been broadcast.",
            "image_id": image_id, "guest_binary_sha256": sha256(guest.read_bytes()).hexdigest(), "payments": payments}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--r0vm", type=Path, required=True)
    parser.add_argument("--guest", type=Path, required=True)
    parser.add_argument("--verify", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.archive, args.r0vm, args.guest, args.verify, args.out)
    save(args.out / "summary.json", report)


if __name__ == "__main__":
    main()

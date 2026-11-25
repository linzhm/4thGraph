"""Prove verifier funding checkpoints against the actual regtest spend outpoints."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import lzma
import os
from pathlib import Path
import subprocess
from time import perf_counter

from funding_checkpoint import from_funding
from run_covenant_backtrace_regtest import save
from shared.transaction import Transaction


def altered(value):
    return bytes([value[0] ^ 1]) + value[1:]


def funding_samples(archive_path, approved):
    if len(approved) != 32:
        raise ValueError("expected the policy's SHA-256 of the serialized verifier script field")
    with lzma.open(archive_path, "rt") as stream:
        archive = json.load(stream)

    samples = []
    for row in archive["summary"]["confirmations"]:
        raw_spend = bytes.fromhex(archive["transactions"][row["txid"]])
        spend = Transaction.parse(raw_spend)
        if spend.txid() != row["txid"]:
            raise ValueError("archive payment does not match its txid")
        current = spend.inputs[0]
        raw = bytes.fromhex(archive["transactions"][current.txid[::-1].hex()])
        checkpoint, lock_hash = from_funding(raw)
        if lock_hash != approved or current.vout or checkpoint.continued_txid_wire() != current.txid:
            raise ValueError("checkpoint does not open the actual approved funding output")
        samples.append((spend, raw, checkpoint))
    if len(samples) != 2 or samples[0][0].inputs[0].outpoint() == samples[1][0].inputs[0].outpoint():
        raise ValueError("expected two independently funded verifier outputs")
    return samples


def verify_fundings(samples, proofs, verify, guest, image_id, approved, env):
    records = []
    for (spend, raw, checkpoint), (receipt, elapsed) in zip(samples, proofs, strict=True):
        outpoint = spend.inputs[0].outpoint()
        digest = checkpoint.digest(outpoint, approved)
        output = subprocess.check_output([verify, receipt, image_id, digest.hex()], text=True, env=env)
        result = dict(field.split("=") for field in output.split())
        payload = receipt.read_bytes()
        if result["kind"] != "succinct" or int(result["receipt_bytes"]) != len(payload):
            raise ValueError("unexpected proof encoding")
        records.append({
            "source_spend_txid": spend.txid(),
            "actual_verifier_outpoint": f"{outpoint[:32][::-1].hex()}:0",
            "funding_bytes": len(raw),
            "output_count_offset": checkpoint.output_count_offset,
            "satoshis": checkpoint.value,
            "processed_bytes": checkpoint.processed,
            "midstate": checkpoint.state.hex(),
            "suffix": checkpoint.suffix.hex(),
            "checkpoint_bytes": len(checkpoint.encode()),
            "statement_digest": digest.hex(),
            "prove_wall_seconds": elapsed,
            "native_verify_seconds": float(result["native_verify_seconds"]),
            "receipt_bytes": len(payload),
            "receipt_sha256": sha256(payload).hexdigest(),
        })
        print(f"{spend.txid()} {elapsed:.2f}s {len(payload)} B", flush=True)

    spend, _, proof_input = samples[0]
    outpoint = spend.inputs[0].outpoint()
    failures = {
        "different_actual_verifier": (samples[1][0].inputs[0].outpoint(), approved, proof_input),
        "replay_with_other_funding_data": (samples[1][0].inputs[0].outpoint(), approved, samples[1][2]),
        "wrong_vout": (outpoint[:32] + b"\x01\0\0\0", approved, proof_input),
        "wrong_lock": (outpoint, altered(approved), proof_input),
        "wrong_state": (outpoint, approved, replace(proof_input, state=altered(proof_input.state))),
        "wrong_suffix": (outpoint, approved, replace(proof_input, suffix=altered(proof_input.suffix))),
        "wrong_output_boundary": (outpoint, approved, replace(proof_input,
                                  output_count_offset=proof_input.output_count_offset + 1)),
        "wrong_value": (outpoint, approved, replace(proof_input, value=proof_input.value + 1)),
        "wrong_total_length": (outpoint, approved, replace(proof_input, length=proof_input.length + 64,
                               processed=proof_input.processed + 64)),
    }
    rejections = {}
    for name, (point, lock_hash, checkpoint) in failures.items():
        digest = checkpoint.digest(point, lock_hash)
        status = subprocess.run([verify, proofs[0][0], image_id, digest.hex()],
                                env=env, text=True, capture_output=True)
        if status.returncode == 0 or "different checkpoint digest" not in status.stderr:
            raise ValueError(f"expected a cryptographic statement rejection for {name}")
        rejections[name] = status.stderr.strip()

    return {
        "scope": "Host RISC Zero receipt verification for the two actual archived funding outpoints.",
        "image_id": image_id,
        "guest_binary_sha256": sha256(guest.read_bytes()).hexdigest(),
        "approved_verifier_script_field_sha256": approved.hex(),
        "fundings": records,
        "rejections": rejections,
    }


def run(archive_path, vm, guest, verify, approved, out):
    samples = funding_samples(archive_path, approved)
    out.mkdir()
    env = {key: value for key, value in os.environ.items() if key != "RISC0_DEV_MODE"}
    image_id = subprocess.check_output([vm, "--elf", guest, "--id"], text=True, env=env).strip()
    proofs = []
    for index, (_, raw, _) in enumerate(samples):
        private = out / f"funding-{index}.bin"
        receipt = out / f"funding-{index}-receipt.bin"
        private.write_bytes(len(raw).to_bytes(4, "little") + raw)
        started = perf_counter()
        with (out / f"funding-{index}.log").open("x") as log:
            subprocess.run([vm, "--elf", guest, "--initial-input", private, "--receipt-kind", "succinct",
                            "--receipt", receipt], check=True, stdout=log, stderr=subprocess.STDOUT, env=env)
        proofs.append((receipt, perf_counter() - started))
    return verify_fundings(samples, proofs, verify, guest, image_id, approved, env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--r0vm", type=Path, required=True)
    parser.add_argument("--guest", type=Path, required=True)
    parser.add_argument("--verify", type=Path, required=True)
    parser.add_argument("--lock-field-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = run(args.archive, args.r0vm, args.guest, args.verify, bytes.fromhex(args.lock_field_sha256), args.out)
    save(args.out / "summary.json", summary)


if __name__ == "__main__":
    main()

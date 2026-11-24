"""Turn a BLS12-381 Groth16 verification key, proof and signals into BSV scripts."""

import argparse
import json
from pathlib import Path

from descriptor import EXPERIMENTS, VerifierDescriptor
from snarkjs_adapter import load_artifacts
from verifier import verify_host


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verification_key", type=Path)
    parser.add_argument("proof", type=Path)
    parser.add_argument("public_signals", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", choices=EXPERIMENTS, default="gamma")
    args = parser.parse_args()
    inputs = (args.verification_key, args.proof, args.public_signals)
    key, signals, proof = load_artifacts(*(json.loads(path.read_text()) for path in inputs))
    if not verify_host(key, signals, proof):
        parser.error("proof does not verify for the supplied public signals")
    descriptor = VerifierDescriptor(key, signals, args.profile)
    lock, _ = descriptor.build_lock()
    unlock = descriptor.build_unlock(proof)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in (("descriptor", descriptor.encode()), ("locking", lock), ("unlocking", unlock)):
        (args.out / (name + ".hex")).write_text(data.hex() + "\n")
    print(json.dumps({"descriptor_id": descriptor.identifier().hex(), "lock_bytes": len(lock),
                      "unlock_bytes": len(unlock)}, indent=2))


if __name__ == "__main__":
    main()

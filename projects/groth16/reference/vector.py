"""Generate the deterministic research vector and optional complete raw transactions."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from statistics import median
from time import perf_counter_ns

from descriptor import DEFAULT_EXPERIMENT, EXPERIMENTS, PROFILES, VerifierDescriptor
from fixtures import fixture, transactions
from verifier import proof_fields


def benchmark(lock, unlock, samples):
    from shared.chain_gang import validate_at_heights

    funding, payment = transactions(lock, unlock, 2)
    context = dict(spend_height=4, activation_height=3, utxo_heights=[3])
    validate_at_heights(payment, [funding], **context)
    timings = []
    for _ in range(samples):
        start = perf_counter_ns()
        validate_at_heights(payment, [funding], **context)
        timings.append((perf_counter_ns() - start) / 1_000_000)
    return round(median(timings), 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts-out", type=Path)
    parser.add_argument("--experiment", choices=EXPERIMENTS, default=DEFAULT_EXPERIMENT)
    parser.add_argument("--benchmark", type=int, metavar="SAMPLES", default=0)
    args = parser.parse_args()
    if args.benchmark < 0:
        parser.error("--benchmark requires a nonnegative sample count")
    key, public_inputs, proof = fixture()
    sizes = {}
    descriptor = VerifierDescriptor(key, public_inputs, args.experiment)
    lock, _ = descriptor.build_lock()
    unlock = descriptor.build_unlock(proof)
    for profile in PROFILES:
        other = VerifierDescriptor(key, public_inputs, profile)
        profile_lock, sections = other.build_lock()
        profile_unlock = other.build_unlock(proof)
        sizes[profile] = {
            "locking_bytes": len(profile_lock), "unlocking_bytes": len(profile_unlock), "sections": sections,
        }
        if args.benchmark:
            sizes[profile]["chain_gang_median_ms"] = benchmark(profile_lock, profile_unlock, args.benchmark)

    funding, payment = transactions(lock, unlock, 2)
    result = {
        "curve": "BLS12-381",
        "experiment": args.experiment,
        "public_inputs": public_inputs,
        "descriptor": descriptor.encode().hex(),
        "descriptor_id": descriptor.identifier().hex(),
        "proof_coordinates": [f"{coordinate:096x}" for coordinate in proof_fields(proof)],
        "locking_sha256": sha256(lock).hexdigest(),
        "unlocking_sha256": sha256(unlock).hexdigest(),
        "funding_txid": funding.txid(),
        "spending_txid": payment.txid(),
        "profiles": sizes,
    }
    if args.scripts_out:
        args.scripts_out.mkdir(parents=True, exist_ok=True)
        for name, raw in (
            ("locking", lock), ("unlocking", unlock), ("funding", funding.serialize()), ("spending", payment.serialize()),
        ):
            (args.scripts_out / (name + ".hex")).write_text(raw.hex() + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

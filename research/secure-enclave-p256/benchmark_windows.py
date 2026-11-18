"""Paired, single-threaded Tx.validate benchmark for P2PKH-R1."""
import argparse
import hashlib
import json
import os
import platform
from importlib.metadata import version
from pathlib import Path
from time import perf_counter_ns

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import SIGHASH, Script, Tx, TxIn, TxOut, sig_hash_preimage

from handwritten import locking_script, unlocking_script

SHARDS = 20
PAIRS = 50
BATCH = 1000
CASES = 8
VERSIONS = {"joint2": 3, "split4": 4}


def corpus(ver):
    cases = []
    for i in range(CASES):
        # Public offline test keys. RFC 6979 makes the corpus repeatable across machines.
        key = ec.derive_private_key(7 + i, ec.SECP256R1())
        pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        owner = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
        lock = locking_script(owner, version=ver)
        parent = Tx(1, [TxIn(f"{17+i:02x}" * 32, 0, Script())], [TxOut(1000, lock)], 0)
        dest = [TxOut(900-i, Script.parse_string("OP_1"))]
        unsigned = Tx(1, [TxIn(parent.id(), 0, Script())], dest, 0)
        p = sig_hash_preimage(unsigned, 0, Script.parse_string("OP_CHECKSIG"), 1000, SIGHASH(0x41))
        msg = b"BSV/SecureEnclave/P256/v1\x00" + p
        r, s = utils.decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        unlock = unlocking_script(parent.serialize(), p, pub, r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        tx = Tx(1, [TxIn(parent.id(), 0, unlock)], dest, 0)
        cases.append((tx, [parent]))
    return cases


def execute(cases, count):
    for i in range(count):
        tx, parents = cases[i % len(cases)]
        tx.validate(parents)  # PyO3 raises on any failure.


def run(shard, output):
    if not 0 <= shard < SHARDS:
        raise ValueError("invalid shard")
    vectors = {name: corpus(ver) for name, ver in VERSIONS.items()}
    result = {"shard": shard, "commit": os.environ.get("GITHUB_SHA"), "python": platform.python_version(),
              "engine": version("tx-engine"), "cryptography": version("cryptography"), "batch_size": BATCH,
              "cpu": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                           if line.startswith("model name")), platform.machine()),
              "fixture_ids": {name: [tx.id() for tx, _ in cases] for name, cases in vectors.items()},
              "samples_ns": {name: [] for name in VERSIONS}}
    for cases in vectors.values():
        execute(cases, CASES * 4)
    for batch in range(PAIRS):
        order = tuple(VERSIONS) if (batch + shard) % 2 == 0 else tuple(reversed(VERSIONS))
        for name in order:
            start = perf_counter_ns()
            execute(vectors[name], BATCH)
            elapsed = perf_counter_ns() - start
            result["samples_ns"][name].append(elapsed)
        if (batch + 1) % 5 == 0:
            print(f"shard {shard}: {batch+1}/{PAIRS} paired batches complete", flush=True)
    output.write_text(json.dumps(result) + "\n")


def summarize(directory):
    records = [json.loads(p.read_text()) for p in sorted(directory.glob("*.json"))]
    if sorted(r["shard"] for r in records) != list(range(SHARDS)):
        raise ValueError("missing or duplicated shard")
    for r in records:
        if (r["batch_size"] != BATCH or r["commit"] != os.environ["GITHUB_SHA"]
                or r["fixture_ids"] != records[0]["fixture_ids"]
                or r["engine"] != "0.13.1" or set(r["samples_ns"]) != set(VERSIONS)):
            raise ValueError("inconsistent benchmark records")
    summary = {}
    for name in VERSIONS:
        samples = [sample for r in records for sample in r["samples_ns"][name]]
        if any(len(r["samples_ns"][name]) != PAIRS for r in records) or min(samples) <= 0:
            raise ValueError("incomplete timing samples")
        count = len(samples) * BATCH
        if count != 1_000_000:
            raise ValueError("expected one million completed validations per version")
        seconds = sum(samples) / 1e9
        summary[name] = {"validations": count, "serial_seconds_sum": seconds,
                         "mean_ms": seconds * 1000 / count, "validations_per_second": count / seconds}
    summary["split4_over_joint2_time_ratio"] = summary["split4"]["serial_seconds_sum"] / summary["joint2"]["serial_seconds_sum"]
    summary["split4_faster_shards"] = sum(sum(r["samples_ns"]["split4"]) < sum(r["samples_ns"]["joint2"]) for r in records)
    summary["shards"] = SHARDS
    summary["cpu_models"] = sorted({r["cpu"] for r in records})
    print(json.dumps(summary, sort_keys=True))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out:
        out.write("### P2PKH-R1 · 1,000,000 full validations per window\n\n")
        out.write("```json\n" + json.dumps(summary, indent=2) + "\n```\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    cmd = parser.add_subparsers(dest="command", required=True)
    worker = cmd.add_parser("run")
    worker.add_argument("shard", type=int)
    worker.add_argument("output", type=Path)
    aggregator = cmd.add_parser("summarize")
    aggregator.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "run":
        run(args.shard, args.output)
    else:
        summarize(args.directory)

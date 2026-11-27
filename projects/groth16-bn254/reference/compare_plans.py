"""Compare BN254 verifier plans on the same two fixture statements."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.script import asm
from fourthgraph.bsv.transaction import Input, Output, Transaction, blob
from fourthgraph.replay.groth16_bn254 import sign_spend
from fourthgraph.replay.workflow import TestKeys, UTXO, stack_peaks
from fourthgraph.verification.groth16_bn254 import ScriptVerifier, build_adapter, public_signals, runar_proof

PROJECT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT / "versions/v0.1.0/fixture.json"
PLANS = (
    ("baseline", False, "", 0),
    ("fixed-pairings", True, "affine", 0),
    ("projective-binary", True, "projective-binary", 0),
    ("projective-naf", True, "projective-naf", 0),
    ("naf-mod-64", True, "projective-naf", 64),
    ("naf-mod-128", True, "projective-naf", 128),
    ("naf-mod-256", True, "projective-naf", 256),
    ("naf-mod-512", True, "projective-naf", 512),
)


def compile_case(verifier, keys, case, options):
    signals = public_signals(json.dumps(case["public"]))
    proof = runar_proof(json.dumps(case["proof"]))
    template = verifier.emit(signals, fixed_msm=True, **options)
    owner = keys.public["operator"]
    prefix = asm("OP_0 OP_CHECKSIGVERIFY")
    if not template.startswith(prefix):
        raise ValueError("unexpected Rúnar owner slot")
    lock = verifier.owner_guard(owner) + template[len(prefix):]
    witness = verifier.emit(signals, proof, **options)
    return lock, witness


def time_engines(node, tx, parent, samples):
    context = dict(spend_height=104, utxo_heights=(103,), activation_height=2)
    rpc_ms, chain_ms = [], []
    for i in range(samples + 1):
        start = perf_counter_ns()
        if node.verdicts(tx, (parent,), timeout_us=15000, **context) != [True]:
            raise ValueError("BSV Node rejected a valid fixture")
        rpc = (perf_counter_ns() - start) / 1e6
        start = perf_counter_ns()
        validate_at_heights(tx, (parent,), **context)
        chain = (perf_counter_ns() - start) / 1e6
        if i:
            rpc_ms.append(round(rpc, 3))
            chain_ms.append(round(chain, 3))
    return dict(node_rpc_ms=rpc_ms, chain_gang_ms=chain_ms,
                node_rpc_median_ms=median(rpc_ms), chain_gang_median_ms=median(chain_ms))


def measure(node, keys, lock, witness, samples):
    parent = Transaction((Input(bytes(32), 0),), (Output(2_000_000, lock),))
    unsigned = Transaction((Input(parent.txid_wire(), 0),), (Output(1_900_000, asm("OP_1")),))
    tx = sign_spend(unsigned, parent, witness, keys)
    timings = time_engines(node, tx, parent, samples)
    return dict(lock_bytes=len(lock), lock_sha256=sha256(lock).hexdigest(), witness_bytes=len(witness),
                witness_sha256=sha256(witness).hexdigest(),
                path_bytes=len(blob(lock))+len(blob(tx.inputs[0].script)),
                stack=stack_peaks(tx, (UTXO(parent, 0),)), **timings)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--runar", required=True, type=Path)
    cli.add_argument("--go", default="go")
    cli.add_argument("--samples", type=int, default=5)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    if args.samples < 1:
        cli.error("at least one timing sample is required")
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN or os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT") != "2":
        raise ValueError("use the pinned chain-gang package and Chronicle height 2")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    fixture_bytes = FIXTURE.read_bytes()
    fixture = json.loads(fixture_bytes)
    verification_key = json.dumps(fixture["verification_key"]).encode()
    keys = TestKeys()
    if keys.public["operator"].hex() != fixture["owner_public_key"]:
        raise ValueError("unexpected fixture signing key")
    variants = {}
    with TemporaryDirectory(prefix="bn254-compare-") as temporary:
        adapter = Path(temporary) / "adapter"
        build_adapter(args.runar, adapter, go=args.go)
        verifier = ScriptVerifier(adapter, verification_key, temporary)
        for name, compact, subgroup, threshold in PLANS:
            options = dict(compact_statement=compact, compact_subgroup=subgroup, modulo_threshold=threshold)
            results = {}
            for label in ("wrap", "other"):
                try:
                    lock, witness = compile_case(verifier, keys, fixture[label], options)
                    results[label] = measure(node, keys, lock, witness, args.samples)
                except (RuntimeError, ValueError) as error:
                    results[label] = {"error": str(error)}
            variants[name] = dict(options=options, cases=results)
            print(name, {case: row.get("error", (row.get("lock_bytes"), row.get("witness_bytes"),
                                                row.get("node_rpc_median_ms"), row.get("chain_gang_median_ms")))
                         for case, row in results.items()}, flush=True)
    evidence = dict(fixture_sha256=sha256(fixture_bytes).hexdigest(), bsv_node_version=node.version,
                    chain_gang=engine, samples_per_case=args.samples, plans=variants)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

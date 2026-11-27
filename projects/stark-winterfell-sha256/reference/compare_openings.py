"""Compare lock size and verification time for two Merkle opening lowerings."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from statistics import median
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from fourthgraph.benchmark.validation import Node, chain_metadata, chain_verdict
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, encode_num, number, push
from fourthgraph.bsv.transaction import Input, Output, Transaction, compact
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.merkle import merkle_sha256_root
from fourthgraph.compiler.source import SourceCompiler

from opening_replay import PROJECT, RELEASE, SOURCE, mutations, script_verdict

ORIGINAL = PROJECT / "versions/v0.1.0"
COMPOSED = "v01_composed"
INTRINSIC = "v02_intrinsic"


def comparison_word():
    path = PROJECT / "hashes.fth"
    parent = SourceCompiler(path.read_text(), source_path=path).words["stark-sha256-merkle-parent"]
    checked = compile_word(parent, "stack").script
    recorded = next(row for row in json.loads((ORIGINAL / "hash-checks.json").read_text())["vectors"]
                    if row["name"] == "merkle-parent")
    if sha256(checked).hexdigest() != recorded["script_sha256"]:
        raise ValueError("the checked parent no longer matches the v0.1.0 artifact")

    intrinsic = merkle_sha256_root(13, b"\x02")
    specialized = asm("OP_CAT OP_2 OP_SWAP OP_CAT OP_SHA256")
    if intrinsic.code.count(specialized) != 13:
        raise ValueError("expected exactly 13 specialized parent blocks")
    code = intrinsic.code.replace(specialized, checked)
    return replace(intrinsic, code=code, expansion_cost=len(code)), len(checked), len(specialized)


def measure_timings(composed, intrinsic, samples):
    for check in (composed, intrinsic):
        if not check():
            raise ValueError("an engine rejected a valid opening during warmup")

    measurements = {COMPOSED: [], INTRINSIC: []}
    pair = ((COMPOSED, composed), (INTRINSIC, intrinsic))
    for trial in range(samples):
        for name, check in pair if trial % 2 == 0 else reversed(pair):
            start = perf_counter_ns()
            accepted = check()
            measurements[name].append((perf_counter_ns() - start) / 1000)
            if not accepted:
                raise ValueError(f"an engine rejected {name} during timing")
    differences = [old - new for old, new in zip(measurements[COMPOSED], measurements[INTRINSIC], strict=True)]
    return {
        **{name: round(median(values), 3) for name, values in measurements.items()},
        "median_paired_saving": round(median(differences), 3),
    }


def measure_variant(lock, proof_digest, ordinal, inputs, controls, node):
    parent = Transaction((Input(bytes.fromhex(proof_digest), ordinal),), (Output(1000, lock),))
    tx = Transaction((Input(parent.txid_wire(), 0, b"".join(map(push, inputs))),), (Output(900, number(1)),))

    peak = traversed = 0

    def observe(main, alt):
        nonlocal peak, traversed
        traversed += 1
        peak = max(peak, sum(map(len, main)) + sum(map(len, alt)))

    main, alt = evaluate(lock, inputs, observe_stack=observe)
    if main != [b"\x01"] or alt:
        raise ValueError("the local evaluator rejected a valid opening")
    for label, stack in controls:
        bad = tx.with_script(0, b"".join(map(push, stack)))
        if script_verdict(lock, stack) or node.verdicts(bad, (parent,)) != [False] or chain_verdict(bad, (parent,)):
            raise ValueError(f"an engine accepted {label} for query {ordinal}")

    unlock = tx.inputs[0].script
    stats = {
        "lock_bytes": len(lock),
        "unlock_bytes": len(unlock),
        "serialized_lock_and_unlock_fields_bytes": len(compact(len(lock))) + len(lock)
                                                    + len(compact(len(unlock))) + len(unlock),
        "development_evaluator_stack_payload_peak_bytes": peak,
        "opcodes_and_pushes_traversed_by_development_evaluator": traversed - 1,
        "both_engines_accept_valid": True,
        "both_engines_reject": [label for label, _ in controls],
    }
    return stats, lambda: node.verdicts(tx, (parent,)) == [True], lambda: chain_verdict(tx, (parent,))


def measure(binary, proof_path, recorded, reference, node, samples):
    current, next_state, ordinal = (recorded[key] for key in ("current", "next", "query"))
    result = int(subprocess.check_output([binary, "prove", str(current), proof_path]))
    proof = proof_path.read_bytes()
    if result != next_state or sha256(proof).hexdigest() != recorded["proof_sha256"]:
        raise ValueError(f"proof differs from the release for {current}")
    opening = json.loads(subprocess.check_output(
        [binary, "trace-opening", str(current), str(next_state), str(ordinal), proof_path]
    ))
    index = opening["index"]
    root, row, path = (bytes.fromhex(opening[key]) for key in ("root", "row", "path"))
    if root.hex() != recorded["trace_root"] or index != recorded["index"]:
        raise ValueError(f"opening differs from the release for query {ordinal}")

    source = SOURCE.read_text()
    alternate = source.replace("merkle-sha256-root #13 02", "comparison-merkle-root")
    if alternate == source:
        raise ValueError("could not locate the depth-13 Merkle call in the fixture")
    variants = {
        COMPOSED: (alternate, {"comparison-merkle-root": reference}),
        INTRINSIC: (source, {}),
    }
    inputs = [row, path, encode_num(index)]
    controls = list(mutations(row, path, index))
    results, node_checks, chain_checks = {}, {}, {}

    for name, (text, vocabulary) in variants.items():
        frontend = SourceCompiler(text, vocabulary=vocabulary, source_path=SOURCE, bindings={"trace-root": root})
        lock = compile_word(frontend.words["verify-trace-opening"], "stack", spend_entry=True).script
        if name == INTRINSIC and sha256(lock).hexdigest() != recorded["lock_sha256"]:
            raise ValueError(f"compiled lock differs from the release for query {ordinal}")
        results[name], node_checks[name], chain_checks[name] = measure_variant(
            lock, recorded["proof_sha256"], ordinal, inputs, controls, node,
        )
    return {
        "query_ordinal": ordinal, "index": index, "proof_bytes": len(proof), "variants": results,
        "bsv_node_verifyscript_rpc_us": measure_timings(node_checks[COMPOSED], node_checks[INTRINSIC], samples),
        "chain_gang_parse_and_verify_us": measure_timings(chain_checks[COMPOSED], chain_checks[INTRINSIC], samples),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=201)
    parser.add_argument("--output", type=Path, default=PROJECT / "workspace/build/opening-comparison.json")
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")

    try:
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        reference, checked, specialized = comparison_word()
        records = json.loads((RELEASE / "opening-checks.json").read_text())["openings"]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=args.output.parent) as scratch:
            proof_path = Path(scratch) / "counter.proof"
            results = [measure(args.binary.resolve(), proof_path, row, reference, node, args.samples)
                       for row in records]
        report = {
            "comparison": "Only the parent hash block changes, using the v0.1 checked hash word or the v0.2 specialized hash block",
            "same_witness_and_root": True,
            "v01_checked_parent_bytes": checked, "v02_specialized_parent_bytes": specialized,
            "synthetic_previous_outputs": True, "paired_samples_per_opening": args.samples, "results": results,
            "bsv_node_version": node.version, "chain_gang": chain_metadata(),
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(args.output)


if __name__ == "__main__":
    main()

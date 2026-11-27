"""Replay the same Schnorr spends with literal and reconstructed OTDA preimages."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path

from compare import (compile_candidate, compiled_template, payment_case, plans, require_verdict)
from schnorr_script import compile_reconstructed_unlock, output_reconstruction
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.otda_reconstruction import shorter_reconstruction


def replay(node, label, lock, offset, pattern, shape):
    literal, parents = payment_case(lock, offset, 0x61, shape)
    reconstructed = literal
    for index, txin in enumerate(literal.inputs):
        stack, alt = evaluate(txin.script)
        preimage, witness, mode = stack
        if mode or alt or len(witness) != 160:
            raise ValueError("expected the ordinary Schnorr witness")
        program = shorter_reconstruction(preimage, literal.outputs, (pattern,))
        if program is None:
            continue
        script = compile_reconstructed_unlock(program, witness[:32], witness[32:64], witness[64:128], witness[128:])
        if evaluate(script) != (stack, alt):
            raise ValueError("the reconstructed witness differs from the literal one")
        reconstructed = reconstructed.with_script(index, script)

    for encoding, tx in (("literal", literal), ("reconstructed", reconstructed)):
        require_verdict(node, f"{label}/{shape}/{encoding}", tx, parents, True)
        require_verdict(node, f"{label}/{shape}/{encoding}/changed-locktime", replace(tx, locktime=1), parents, False)
    if shape == (2, 2):
        changed = replace(reconstructed, outputs=tuple(reversed(reconstructed.outputs)))
        require_verdict(node, f"{label}/{shape}/changed-output-order", changed, parents, False)
        if len(reconstructed.serialize()) >= len(literal.serialize()):
            raise ValueError("the Schnorr outputs should have a smaller reconstruction")
    elif reconstructed != literal:
        raise ValueError("exit to a native output should use the literal witness")
    return {
        encoding: {"transaction_bytes": len(tx.serialize()), "txid": tx.txid(),
                   "unlock_bytes": [len(item.script) for item in tx.inputs]}
        for encoding, tx in (("literal", literal), ("reconstructed", reconstructed))
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not os.environ.get("REGTEST_URL"):
        parser.error("run through tools/verify_node.sh --profile raised")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        parser.error("install the project requirements to use pinned chain-gang")

    frozen = json.loads(Path(__file__).with_name("measurements.json").read_text())
    selected = ("source-baseline", frozen["winner"])
    manual, offset = compiled_template(bytes(20))
    builds = {"manual-v0.17.0": manual}
    for plan in plans():
        if plan.name in selected:
            _, lock, _, _ = compile_candidate(plan)
            builds[plan.name] = lock

    rows = {}
    for label, lock in builds.items():
        lock_hash = sha256(lock).hexdigest()
        if lock_hash != frozen["candidates"][label]["lock_sha256"]:
            raise ValueError(f"{label} differs from the frozen literal comparison")
        pattern = output_reconstruction(lock, offset)
        rows[label] = {
            "lock_bytes": len(lock), "lock_sha256": lock_hash, "constructor_bytes": len(pattern.program),
            "2x2": replay(node, label, lock, offset, pattern, (2, 2)),
            "1x1_native_exit": replay(node, label, lock, offset, pattern, (1, 1)),
        }
    report = {"sighash": "0x61", "bsv_node_version": node.version, "chain_gang": engine, "results": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

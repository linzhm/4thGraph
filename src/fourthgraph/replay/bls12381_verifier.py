"""Fund and replay the Forth verifier with two statements under one key."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from fourthgraph.verification.bls12381.affine_witness import LAYOUTS
from fourthgraph.replay.groth16_bls12381 import FIXTURE
from fourthgraph.verification.bls12381.verifier import (
    AFFINE_BYTES, FIELD_BYTES, PACKET_BYTES, Dynamic, public_packet, public_signals,
)
from fourthgraph.verification.bls12381.build import (
    OBJECTIVES, SCRIPT_ERAS, ArithmeticPlan, ForthVerifier, SOURCE, layout_candidates, select_layout,
)
from fourthgraph.replay.groth16_bn254 import LOCK_VALUE, SPEND_FEE, fund, verify_spend
from fourthgraph.workflow.protocol import FLAG, UTXO
from fourthgraph.replay.workflow import stack_peaks
from fourthgraph.benchmark.admission import submit_and_mine
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Input, Output, Transaction

SOURCES = tuple(Dynamic(bits) for bits in (32, 1, 32, 2, 2))


def fixture():
    document = json.loads(FIXTURE.read_bytes())
    key = json.dumps(document["verification_key"])
    cases = tuple((public_signals(json.dumps(document[name]["public"])), json.dumps(document[name]["proof"]))
                  for name in ("wrap", "other"))
    return key, cases


def witness_controls(witnesses, packets, index, proof_packet_bytes, *, layout, line_packet_bytes=0):
    prefix = witnesses[index][:-len(push(packets[index]))]
    proof_start = len(prefix) - proof_packet_bytes
    # (0,2) is on G1 and has order 3.
    torsion = bytes(FIELD_BYTES) + (2).to_bytes(FIELD_BYTES, "little")
    controls = {
        "crossed_statement": prefix + push(packets[1 - index]),
        "g1_outside_subgroup": (prefix[:proof_start] + torsion + prefix[proof_start + len(torsion):]
                                + push(packets[index])),
    }
    if layout in ("projective", "projective-cofactor"):
        other_prefix = witnesses[1 - index][:-len(push(packets[1 - index]))]
        controls["crossed_statement_with_valid_msm"] = (
            prefix[:-AFFINE_BYTES] + other_prefix[-AFFINE_BYTES:] + push(packets[1 - index])
        )
    if layout == "projective-cofactor":
        for index_in_proof, name in enumerate(("a", "c")):
            start = proof_start + PACKET_BYTES + index_in_proof * AFFINE_BYTES
            controls[f"torsion_preimage_{name}"] = (
                prefix[:start] + torsion + prefix[start + AFFINE_BYTES:] + push(packets[index])
            )
    if line_packet_bytes:
        start = len(push(bytes(line_packet_bytes))) - line_packet_bytes
        controls["modified_committed_lines"] = (
            prefix[:start] + bytes([prefix[start] ^ 1]) + prefix[start + 1:] + push(packets[index])
        )
    return controls


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=SOURCE)
    cli.add_argument("--entry", help="Forth definition to compile and replay")
    cli.add_argument("--tx-version", type=int, choices=(1, 2), default=2)
    cli.add_argument("--script-era", choices=SCRIPT_ERAS, default="genesis")
    cli.add_argument("--arithmetic-plan", type=Path, help="replay an explicit Fp2 and residue lowering plan")
    layout = cli.add_mutually_exclusive_group()
    layout.add_argument("--objective", choices=OBJECTIVES)
    layout.add_argument("--witness-layout", choices=LAYOUTS)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the Chronicle-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("the replay requires a fresh peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    key, cases = fixture()
    source = args.source.read_bytes()
    plan = ArithmeticPlan.read(args.arithmetic_plan) if args.arithmetic_plan else None
    if args.objective:
        candidates = layout_candidates(key, source, SOURCES, script_era=args.script_era, entry=args.entry,
                                       source_path=args.source, plan=plan)
        verifier, artifact = select_layout(candidates, args.objective)
        lock = bytes.fromhex(artifact["script_hex"])
    else:
        verifier = ForthVerifier(key, source, witness_layout=args.witness_layout or "projective",
                                 script_era=args.script_era, entry=args.entry, source_path=args.source, plan=plan)
        lock = verifier.compile(SOURCES)
        artifact = verifier.artifact(SOURCES, None, lock)
    packets = [public_packet(SOURCES, signals) for signals, _ in cases]
    witnesses = [verifier.witness(signals, proof, sources=SOURCES) for signals, proof in cases]
    rows = []
    for index, (signals, _) in enumerate(cases):
        native, bootstrap = fund(node, args.tx_version)
        version = args.tx_version
        deployment = Transaction((Input(bootstrap.txid_wire(), 0),), (Output(LOCK_VALUE, lock),), version=version)
        deployment = native.unlock(deployment, 0, bootstrap, FLAG, None)
        deployed = submit_and_mine(node, deployment)
        if not deployed["mined"]:
            raise ValueError(f"could not deploy verifier: {deployed}")
        draft = Transaction((Input(deployment.txid_wire(), 0),),
                            (Output(LOCK_VALUE - SPEND_FEE, native.output.script),), version=version)
        invalid = witness_controls(witnesses, packets, index, artifact["proof_packet_bytes"],
                                   layout=verifier.witness_layout,
                                   line_packet_bytes=artifact.get("pairing_line_packet_bytes", 0))
        controls = {
            name: verify_spend(node, activation, draft.with_script(0, witness), deployment, deployed["height"],
                               expected=False)
            for name, witness in invalid.items()
        }
        spend = draft.with_script(0, witnesses[index])
        result = verify_spend(node, activation, spend, deployment, deployed["height"], expected=True)
        deploy_bytes, spend_bytes = len(deployment.serialize()), len(spend.serialize())
        rows.append({
            "public_signals": tuple(map(str, signals)), "deploy": deployed, "spend": result, "controls": controls,
            "deployment_raw": deployment.serialize().hex(),
            "deployment_bytes": deploy_bytes, "spend_bytes": spend_bytes,
            "total_bytes": deploy_bytes + spend_bytes, "witness_bytes": len(witnesses[index]),
            "stack_payload": stack_peaks(spend, (UTXO(deployment, 0),)),
        })
    report = {
        "node_version": node.version, "chain_gang": engine, "activation_height": activation,
        "transaction_version": args.tx_version, "fixture_sha256": sha256(FIXTURE.read_bytes()).hexdigest(),
        "artifact": artifact, "statements": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

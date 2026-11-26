"""Fund and replay the Forth verifier with two statements under one key."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from bls12381.affine_witness import LAYOUTS
from bls12381.fixed_replay import FIXTURE
from bls12381.verifier import AFFINE_BYTES, FIELD_BYTES, Dynamic, public_packet, public_signals
from build_verifier import OBJECTIVES, SCRIPT_ERAS, ForthVerifier, SOURCE, layout_candidates, select_layout
from groth16_replay import LOCK_VALUE, SPEND_FEE, fund, verify_spend
from protocol import FLAG, UTXO
from replay import stack_peaks
from shared.benchmark_admission import submit_and_mine
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.script import push
from shared.transaction import Input, Output, Transaction

SOURCES = tuple(Dynamic(bits) for bits in (32, 1, 32, 2, 2))


def fixture():
    document = json.loads(FIXTURE.read_bytes())
    key = json.dumps(document["verification_key"])
    cases = tuple((public_signals(json.dumps(document[name]["public"])), json.dumps(document[name]["proof"]))
                  for name in ("wrap", "other"))
    return key, cases


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=SOURCE)
    cli.add_argument("--entry", help="Forth definition to compile and replay")
    cli.add_argument("--tx-version", type=int, choices=(1, 2), default=2)
    cli.add_argument("--script-era", choices=SCRIPT_ERAS, default="genesis")
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
    if args.objective:
        candidates = layout_candidates(key, source, SOURCES, script_era=args.script_era, entry=args.entry,
                                       source_path=args.source)
        verifier, artifact = select_layout(candidates, args.objective)
        lock = bytes.fromhex(artifact["script_hex"])
    else:
        verifier = ForthVerifier(key, source, witness_layout=args.witness_layout or "projective",
                                 script_era=args.script_era, entry=args.entry, source_path=args.source)
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
        prefix = witnesses[index][:-len(push(packets[index]))]
        other_prefix = witnesses[1 - index][:-len(push(packets[1 - index]))]
        proof_start = len(prefix) - artifact["proof_packet_bytes"]
        # (0,2) is on G1 and has order 3.
        torsion = bytes(FIELD_BYTES) + (2).to_bytes(FIELD_BYTES, "little")
        invalid = {
            "crossed_statement": prefix + push(packets[1 - index]),
            "g1_outside_subgroup": (prefix[:proof_start] + torsion + prefix[proof_start + len(torsion):]
                                    + push(packets[index])),
        }
        if verifier.witness_layout == "projective":
            invalid["crossed_statement_with_valid_msm"] = (
                prefix[:-AFFINE_BYTES] + other_prefix[-AFFINE_BYTES:] + push(packets[1 - index])
            )
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

"""Replay the current BLS12-381 verifier and the selected nChain builds on Genesis."""

import argparse
import json
import os
from pathlib import Path

from replay_plan import FIXTURE, VERSIONS, build, check, digest

from fourthgraph.benchmark.admission import submit_and_mine
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.transaction import Input, Output, Transaction, blob
from fourthgraph.replay.bls12381_verifier import SOURCES, fixture, witness_controls
from fourthgraph.replay.groth16_bn254 import LOCK_VALUE, SPEND_FEE, fund, verify_spend
from fourthgraph.verification.bls12381.verifier import public_packet
from fourthgraph.workflow.protocol import FLAG


def replay(node, activation, lock, witness, crossed):
    native, bootstrap = fund(node, 2)
    deploy = Transaction((Input(bootstrap.txid_wire(), 0),), (Output(LOCK_VALUE, lock),))
    deploy = native.unlock(deploy, 0, bootstrap, FLAG, None)
    admitted = submit_and_mine(node, deploy)
    if not admitted["mined"] or admitted["height"] >= activation:
        raise ValueError("expected the verifier to deploy under Genesis")
    spend = Transaction((Input(deploy.txid_wire(), 0),), (Output(LOCK_VALUE - SPEND_FEE, native.output.script),))
    verify_spend(node, activation, spend.with_script(0, crossed), deploy, admitted["height"], expected=False)
    result = verify_spend(node, activation, spend.with_script(0, witness), deploy, admitted["height"], expected=True)
    spend_info = result["admission"]
    if spend_info["height"] >= activation:
        raise ValueError("expected the verifier to spend under Genesis")
    return dict(lock_bytes=len(lock), lock_sha256=digest(lock), witness_bytes=len(witness),
                witness_sha256=digest(witness), path_bytes=len(blob(lock)) + len(blob(witness)),
                deployment_bytes=admitted["bytes"], spend_bytes=spend_info["bytes"],
                deployment_txid=admitted["txid"], spend_txid=spend_info["txid"],
                valid_spend_mined=True, crossed_statement_rejected_by_both_engines=True)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("scripts", type=Path, help="output from prepare_nchain.py")
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    chain = chain_metadata()
    check("chain-gang revision", chain["commit"], CONTEXT_PIN)
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    check("starting height", node.call("getblockcount", []), 0)
    check("peer count", node.call("getconnectioncount", []), 0)
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])

    plan = json.loads((VERSIONS / "v0.13.0/replay-plan.json").read_bytes())
    check("activation height", activation, plan["script_eras"]["genesis"]["chronicle_activation_height"])
    upstream = json.loads(args.scripts.read_bytes())
    check("fixture SHA-256", upstream["fixture_sha256"], digest(FIXTURE.read_bytes()))
    previous = json.loads((VERSIONS / "v0.11.0/nchain-comparison.json").read_bytes())
    check("nChain revision", upstream["revision"], previous["nchain_revision"])

    artifact, witnesses = build(plan, "genesis")
    _, cases = fixture()
    packets = [public_packet(SOURCES, signals) for signals, _ in cases]
    witness_list = list(witnesses.values())
    lock = bytes.fromhex(artifact["script_hex"])
    project_results = {}
    for index, (label, witness) in enumerate(witnesses.items()):
        controls = witness_controls(witness_list, packets, index, artifact["proof_packet_bytes"],
                                   layout=plan["witness_layout"])
        project_results[label] = replay(node, activation, lock, witness, controls["crossed_statement"])
    replays = {"4thgraph-v0.13.0": project_results}
    for name, variant in upstream["variants"].items():
        label = f"nchain-{name}-{upstream['threshold']}"
        lock = bytes.fromhex(variant["lock"])
        replays[label] = results = {}
        for case, row in zip(witnesses, variant["statements"], strict=True):
            result = replay(node, activation, lock, bytes.fromhex(row["witness"]), bytes.fromhex(row["crossed"]))
            check(f"{label}/{case} path bytes", result["path_bytes"], previous["sweep"][label]["path_bytes"][case])
            results[case] = result

    evidence = dict(fixture_sha256=plan["fixture_sha256"], public_input_bits=previous["public_input_bits"],
                    bsv_node_version=node.version, chain_gang=chain, activation_height=activation,
                    nchain_revision=upstream["revision"], replays=replays)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()

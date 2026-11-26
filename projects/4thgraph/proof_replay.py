"""Build and replay a transparent circuit proof and its binding to a BSV spend."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from circuit_tools import CircuitFixture
from compiler import PROJECT_NAME, PROJECT_VERSION
from lowering import BASELINE
from proof_contract import CURRENT, FIELD, NEXT, ProofContract
from protocol import DEFAULT_TARGET, TARGETS, UTXO, build_artifact
from replay import Replay
from shared.benchmark_validation import ACTIVATION_HEIGHT, CONTEXT_PIN, Node, chain_metadata

FIXTURE = Path(__file__).with_name("proof")


def witness(fixture, contract, tx, current):
    return fixture.prove(current=current, binding=contract.public_binding(tx))


def run_case(replay, circuit, source, bootstrap, slot, *, current, optimization):
    contract = ProofContract(source, circuit.key, current, replay.keys.public, target=replay.target,
                             optimization=optimization)
    parent, deploy = replay.deploy(contract, bootstrap, slot)
    other_parent, other_deploy = replay.deploy(contract, bootstrap, slot + 1)
    previous, foreign = (UTXO(parent, 0),), (UTXO(other_parent, 0),)
    next_state = (current + 1) % (1 << 32)
    tx = contract.unsigned(parent, next_state, version=replay.versions[0])
    other = contract.unsigned(other_parent, next_state, version=replay.versions[-1])
    proof = witness(circuit, contract, tx, current)
    other_proof = witness(circuit, contract, other, current)
    if proof[NEXT] != next_state or proof[CURRENT] != current or other_proof[:3] != proof[:3]:
        raise ValueError("external proof disagrees with the committed state")
    changed = (*proof[:-1], (proof[-1] + 1) % FIELD)
    wrong_state = witness(circuit, contract, tx, (current + 1) % (1 << 32))
    wrong = replace(tx, outputs=(replace(tx.outputs[0], value=tx.outputs[0].value - 1), tx.outputs[1]))
    wrong_effect = witness(circuit, contract, wrong, current)
    controls = {
        "tampered_proof": replay.record(contract.seal(tx, changed), previous, expected=False),
        "wrong_public_state": replay.record(contract.seal(tx, wrong_state), previous, expected=False),
        "valid_proof_for_wrong_output": replay.record(contract.seal(wrong, wrong_effect), previous, expected=False),
        "valid_proof_for_another_outpoint": replay.record(contract.seal(other, proof), foreign, expected=False),
    }
    spend = replay.record(contract.seal(tx, proof), previous)
    other_spend = replay.record(contract.seal(other, other_proof), foreign)
    return {
        "build": build_artifact(contract.describe(), source), "script_bytes": len(contract.root.script),
        "current": current, "next": next_state, "deploy": deploy, "spend": spend, "foreign_deploy": other_deploy,
        "foreign_spend": other_spend, "controls": controls,
        "assignment": list(map(str, proof)), "other_assignment": list(map(str, other_proof)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET)
    parser.add_argument("--current", type=int, default=(1 << 32) - 1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("proof replay requires the height-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("proof replay requires an empty peerless regtest")
    activation = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", ACTIVATION_HEIGHT))
    replay = Replay(node, 3, args.target, activation)
    source = (FIXTURE / "counter.fth").read_bytes()
    with TemporaryDirectory(prefix="4thgraph-counter-") as temporary:
        circuit = CircuitFixture((FIXTURE / "counter.circom").read_bytes(), temporary)
        bootstrap = replay.fund(4)
        cases = {variant: run_case(replay, circuit, source, bootstrap, 2 * i, current=args.current, optimization=variant)
                 for i, variant in enumerate((BASELINE, "stack"))}
        if cases["stack"]["script_bytes"] >= cases[BASELINE]["script_bytes"]:
            raise ValueError("optimized proof verifier did not reduce script bytes")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({
            "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "proof": "transparent-r1cs-assignment",
            "target": args.target, "bsv_node_version": node.version, "chain_gang": engine, "activation_height": activation,
            "bootstrap_raw": bootstrap.serialize().hex(), "circuit": circuit.describe(), "policy": source.decode(),
            "cases": cases,
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()

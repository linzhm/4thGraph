"""Build and replay a transparent circuit proof and its binding to a BSV spend."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from circuit_backend import circuit_words, compile_circuit
from circuit_tools import CircuitFixture
from compiler import PROJECT_NAME, PROJECT_VERSION, evaluate
from lowering import BASELINE, compile_word
from proof_contract import FIELD, NEXT, ROUTE, ProofContract
from protocol import DEFAULT_TARGET, TARGETS, UTXO, build_artifact
from replay import Replay
from shared.benchmark_validation import ACTIVATION_HEIGHT, CONTEXT_PIN, Node, chain_metadata
from shared.evaluate import evaluate as evaluate_script
from shared.script import decode_num, encode_num
from wordsets import U32

FIXTURE = Path(__file__).with_name("proof")


def witness(fixture, contract, tx, current):
    return fixture.prove(current=current, binding=contract.public_binding(tx))


def compare_circuit(circuit, advance, decide, currents):
    advance_script, decide_script = (compile_word(word, "stack").script for word in (advance, decide))
    rows = []
    for current in currents:
        expected_next, = evaluate(advance, current)
        expected_route, = evaluate(decide, expected_next)
        step, alt = evaluate_script(advance_script, [encode_num(current)])
        route, route_alt = evaluate_script(decide_script, step)
        proof = circuit.prove(current=current, binding=(1, 2))
        expected = expected_next, expected_route
        if (alt or route_alt or tuple(map(decode_num, (*step, *route))) != expected
                or (proof[NEXT], proof[ROUTE]) != expected):
            raise ValueError(f"host, Script and R1CS disagree at {current}")
        rows.append({"current": current, "next": expected_next, "route": expected_route,
                     "witness_checked_by_snarkjs": True})
    return rows


def run_case(replay, circuit, source, bootstrap, slot, *, current, next_state, optimization):
    contract = ProofContract(source, circuit, current, replay.keys.public, target=replay.target,
                             optimization=optimization)
    parent, deploy = replay.deploy(contract, bootstrap, slot)
    other_parent, other_deploy = replay.deploy(contract, bootstrap, slot + 1)
    previous, foreign = (UTXO(parent, 0),), (UTXO(other_parent, 0),)
    tx = contract.unsigned(parent, next_state, version=replay.versions[0])
    other = contract.unsigned(other_parent, next_state, version=replay.versions[-1])
    proof = witness(circuit, contract, tx, current)
    other_proof = witness(circuit, contract, other, current)
    wire = circuit.key.current_wire
    if proof[NEXT] != next_state or proof[wire] != current or other_proof[:wire + 1] != proof[:wire + 1]:
        raise ValueError("external proof disagrees with the committed state")
    changed = (*proof[:-1], (proof[-1] + 1) % FIELD)
    wrong_state = witness(circuit, contract, tx, (current + 1) % U32)
    wrong = replace(tx, outputs=(replace(tx.outputs[0], value=tx.outputs[0].value - 1), tx.outputs[1]))
    wrong_effect = witness(circuit, contract, wrong, current)
    changed_locktime = replace(tx, locktime=tx.locktime + 1)
    controls = {
        "tampered_proof": replay.record(contract.seal(tx, changed), previous, expected=False),
        "wrong_public_state": replay.record(contract.seal(tx, wrong_state), previous, expected=False),
        "valid_proof_for_wrong_output": replay.record(contract.seal(wrong, wrong_effect), previous, expected=False),
        "valid_proof_for_another_outpoint": replay.record(contract.seal(other, proof), foreign, expected=False),
        "valid_proof_for_another_locktime": replay.record(
            contract.seal(changed_locktime, proof), previous, expected=False,
        ),
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
    parser.add_argument("--current", type=int, default=U32 - 1)
    parser.add_argument("--generated", action="store_true", help="generate the circuit from workflow.fth")
    parser.add_argument("--compare-domains", action="store_true", help="verify host, Script and generated circuit vectors")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.compare_domains and not args.generated:
        parser.error("--compare-domains requires --generated")
    if not 0 <= args.current < U32:
        parser.error("--current must be a u32")
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("proof replay requires the height-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("proof replay requires an empty peerless regtest")
    activation = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", ACTIVATION_HEIGHT))
    replay = Replay(node, 3, args.target, activation)
    source = (FIXTURE / ("workflow.fth" if args.generated else "counter.fth")).read_bytes()
    circuit_source = compile_circuit(source) if args.generated else (FIXTURE / "counter.circom").read_bytes()
    next_state = (args.current + 1) % U32
    if args.generated:
        advance, decide = circuit_words(source)
        next_state, = evaluate(advance, args.current)
    with TemporaryDirectory(prefix="4thgraph-counter-") as temporary:
        circuit = CircuitFixture(circuit_source, temporary, has_route=args.generated)
        vectors = []
        if args.compare_domains:
            vectors = compare_circuit(circuit, advance, decide, (0, 7, 18, 19, 20, U32 - 2, U32 - 1))
        bootstrap = replay.fund(4)
        cases = {variant: run_case(replay, circuit, source, bootstrap, 2 * i, current=args.current,
                                   next_state=next_state, optimization=variant)
                 for i, variant in enumerate((BASELINE, "stack"))}
        if cases["stack"]["script_bytes"] >= cases[BASELINE]["script_bytes"]:
            raise ValueError("optimized proof verifier did not reduce script bytes")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({
            "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "proof": "transparent-r1cs-assignment",
            "target": args.target, "bsv_node_version": node.version, "chain_gang": engine, "activation_height": activation,
            "bootstrap_raw": bootstrap.serialize().hex(), "circuit": circuit.describe(), "policy": source.decode(),
            "generated": args.generated, "cross_domain_vectors": vectors, "circuit_source": circuit_source.decode(),
            "cases": cases,
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()

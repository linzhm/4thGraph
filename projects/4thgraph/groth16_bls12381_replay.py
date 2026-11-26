"""Replay the BLS12-381 Groth16 fixture with funded BSV regtest transactions."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path

from circuit_backend import circuit_words, compile_circuit
from compiler import evaluate
from groth16_bls12381 import FIELD_BYTES, PACKET_BYTES, Q, ScriptVerifier, public_signals
from groth16_replay import LOCK_VALUE, SOURCE, SPEND_FEE, fund, sign_spend, verify_spend
from protocol import FLAG, UTXO
from replay import TestKeys, stack_peaks
from shared.benchmark_admission import submit_and_mine
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.script import push
from shared.transaction import FORKID, SIGHASH_NONE, Input, Output, Transaction

FIXTURE = Path(__file__).with_name("proof") / "groth16" / "bls12381-counter.json"


def load_fixture():
    fixture = json.loads(FIXTURE.read_bytes())
    verifier = ScriptVerifier(json.dumps(fixture["verification_key"]).encode())
    cases = tuple((public_signals(json.dumps(fixture[name]["public"])), json.dumps(fixture[name]["proof"]))
                  for name in ("wrap", "other"))
    return verifier, cases


def witness_controls(witness, other_witness):
    packet = witness[-PACKET_BYTES:]
    cy = 7 * FIELD_BYTES
    negated = (-int.from_bytes(packet[cy:cy + FIELD_BYTES], "little") % Q).to_bytes(FIELD_BYTES, "little")
    # (0,2) lies on G1 but has order 3.
    g1_torsion = bytes(FIELD_BYTES) + (2).to_bytes(FIELD_BYTES, "little")
    # This affine G2 point lies on the twist but is outside the R-order subgroup.
    g2_torsion = (
        2, 0,
        3813414062821088896965879244443358096636228247329175415943186029072982909461945441384695595240360445618611812101176,
        3568027680765585585945490907042741669558639753778547462314760963815399658271727325750766584361357481230047117262172,
    )
    return {
        "valid_proof_for_another_statement": other_witness,
        "negated_proof_point": push(packet[:cy] + negated + packet[cy + FIELD_BYTES:]),
        "g1_outside_subgroup": push(g1_torsion + packet[2 * FIELD_BYTES:]),
        "g2_outside_subgroup": push(packet[:2 * FIELD_BYTES]
                                    + b"".join(x.to_bytes(FIELD_BYTES, "little") for x in g2_torsion)
                                    + packet[6 * FIELD_BYTES:]),
        "zero_pairing_residue": push(packet[:8 * FIELD_BYTES] + bytes(12 * FIELD_BYTES)),
        "noncanonical_coordinate": push(Q.to_bytes(FIELD_BYTES, "little") + packet[FIELD_BYTES:]),
        "truncated_packet": push(packet[:-1]),
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--tx-version", type=int, choices=(1, 2), default=2)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("Groth16 replay needs the height-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("Groth16 replay requires an empty peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    source = SOURCE.read_bytes()
    advance, decide = circuit_words(source)
    verifier, ((signals, proof), (other_signals, other_proof)) = load_fixture()
    for next_state, route, current, *_ in (signals, other_signals):
        if evaluate(advance, current) != (next_state,) or evaluate(decide, next_state) != (route,):
            raise ValueError("Groth16 fixture public signals disagree with the Forth statement")
    keys = TestKeys()
    owner = keys.public["operator"]
    lock = verifier.compile(signals, owner)
    witness = verifier.witness(signals, proof)
    other_witness = verifier.witness(other_signals, other_proof)

    native, bootstrap = fund(node, args.tx_version)
    deployment = Transaction((Input(bootstrap.txid_wire(), 0),), (Output(LOCK_VALUE, lock),), version=args.tx_version)
    deployment = native.unlock(deployment, 0, bootstrap, FLAG, None)
    deploy = submit_and_mine(node, deployment)
    if not deploy["mined"]:
        raise ValueError(f"could not deploy verifier: {deploy}")
    tx = Transaction((Input(deployment.txid_wire(), 0),), (Output(LOCK_VALUE - SPEND_FEE, native.output.script),),
                     version=args.tx_version)
    valid = sign_spend(tx, deployment, witness, keys)
    invalid = {name: sign_spend(tx, deployment, candidate, keys)
               for name, candidate in witness_controls(witness, other_witness).items()}
    invalid["wrong_sighash"] = sign_spend(tx, deployment, witness, keys, flag=FORKID | SIGHASH_NONE)
    invalid["changed_output_with_stale_signature"] = replace(
        valid, outputs=(replace(valid.outputs[0], value=tx.outputs[0].value - 1),),
    )
    controls = {name: verify_spend(node, activation, spend, deployment, deploy["height"], expected=False)
                for name, spend in invalid.items()}
    result = verify_spend(node, activation, valid, deployment, deploy["height"], expected=True)
    report = {
        "setup": "local-test-only", "bsv_node_version": node.version, "chain_gang": engine,
        "activation_height": activation, "regtest_profile": os.environ.get("SCRIPT_LAB_REGTEST_PROFILE"),
        "transaction_version": args.tx_version, "forth_source_sha256": sha256(source).hexdigest(),
        "circom_source_sha256": sha256(compile_circuit(source)).hexdigest(), "circom_prime": "bls12381",
        "fixture_sha256": sha256(FIXTURE.read_bytes()).hexdigest(),
        "artifact": verifier.artifact(signals, owner, lock), "witness_bytes": len(witness),
        "bootstrap_raw": bootstrap.serialize().hex(), "deployment_raw": deployment.serialize().hex(),
        "deployment_bytes": len(deployment.serialize()), "spend_bytes": len(valid.serialize()),
        "deployment": deploy, "spend": result, "controls": controls,
        "spend_stack_payload": stack_peaks(valid, (UTXO(deployment, 0),)),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

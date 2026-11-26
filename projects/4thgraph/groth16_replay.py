"""Generate test-only Groth16 proofs and spend a BSV verifier output on regtest."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from time import perf_counter

from circuit_backend import emit_circuit, select_circuit
from circuit_tools import CircuitFixture, SNARKJS_PACKAGE
from compiler import SourceCompiler, evaluate
from groth16_script import BASE_FIELD, ScriptVerifier, build_adapter, public_signals, runar_proof
from protocol import FLAG, Outpoint, SignRequest
from replay import TestKeys
from shared.benchmark_admission import submit_and_mine
from shared.benchmark_cases import native_coin
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.chain_gang import validate_at_heights
from shared.script import number, push
from shared.transaction import FORKID, SIGHASH_NONE, Input, Output, Transaction, hash256, preimage_forkid

SOURCE = Path(__file__).with_name("proof") / "workflow.fth"
FUNDING_VALUE, LOCK_VALUE, SPEND_FEE = 4_000_000, 2_000_000, 100_000


def demo_keys(circuit):
    def snark(*args):
        circuit.run(SNARKJS_PACKAGE, "snarkjs", *args)

    snark("powersoftau", "new", "bn128", "8", "initial.ptau")
    snark("powersoftau", "contribute", "initial.ptau", "contributed.ptau",
          "--name=4thGraph-regtest-only", "--entropy=" + secrets.token_hex(32))
    snark("powersoftau", "prepare", "phase2", "contributed.ptau", "phase2.ptau")
    snark("groth16", "setup", "counter.r1cs", "phase2.ptau", "initial.zkey")
    snark("zkey", "contribute", "initial.zkey", "test.zkey",
          "--name=4thGraph-regtest-only", "--entropy=" + secrets.token_hex(32))
    snark("zkey", "verify", "counter.r1cs", "phase2.ptau", "test.zkey")
    snark("zkey", "export", "verificationkey", "test.zkey", "verification_key.json")
    return (circuit.directory / "verification_key.json").read_bytes()


def prove(circuit, program, current, binding, label):
    next_state, = evaluate(program.transition, current)
    route, = evaluate(program.route, next_state)
    expected = tuple(map(str, (next_state, route, current, *binding)))
    inputs = {"current": expected[2], "bindLo": expected[3], "bindHi": expected[4]}
    names = [f"{label}.{part}.json" for part in ("input", "proof", "public")]
    (circuit.directory / names[0]).write_text(json.dumps(inputs))
    circuit.run(SNARKJS_PACKAGE, "snarkjs", "groth16", "fullprove", names[0], "counter_js/counter.wasm",
                "test.zkey", *names[1:])
    circuit.run(SNARKJS_PACKAGE, "snarkjs", "groth16", "verify", "verification_key.json", names[2], names[1])
    proof, public = ((circuit.directory / name).read_bytes() for name in names[1:])
    if public_signals(public) != expected:
        raise ValueError("Groth16 public signals disagree with the Forth statement")
    return expected, proof


def fund(node, version):
    node.call("generate", [101])
    native = native_coin("4thgraph/groth16/funding", FUNDING_VALUE, p2pk=True)
    unsigned = Transaction((), (native.output,), version=version)
    funded = node.call("fundrawtransaction", [unsigned.serialize().hex(), {"changePosition": 1}])
    signed = node.call("signrawtransaction", [funded["hex"]])
    if not signed["complete"]:
        raise ValueError("could not sign fixture funding")
    tx = Transaction.parse(bytes.fromhex(signed["hex"]))
    if tx.version != version or tx.outputs[0] != native.output or not submit_and_mine(node, tx)["mined"]:
        raise ValueError("could not fund fixture")
    return native, tx


def sign_spend(tx, parent, witness, keys, *, flag=FLAG):
    prev = parent.outputs[0]
    digest = hash256(preimage_forkid(tx, 0, prev.value, prev.script, flag))
    request = SignRequest("groth16", Outpoint(parent.txid_wire(), 0), "operator", keys.public["operator"],
                          flag, digest, tx, prev, ())
    return tx.with_script(0, witness + push(keys.sign(request) + bytes([flag])))


def verify_spend(node, activation, tx, parent, parent_height, *, expected):
    if Transaction.parse(tx.serialize()) != tx or tx.inputs[0].txid != parent.txid_wire():
        raise ValueError("invalid replay transaction framing")
    context = {"spend_height": node.call("getblockcount", []) + 1, "utxo_heights": (parent_height,),
               "activation_height": activation}
    start = perf_counter()
    try:
        validate_at_heights(tx, (parent,), **context)
        chain_ok, chain_error = True, None
    except (ValueError, RuntimeError) as error:
        chain_ok, chain_error = False, str(error)
    chain_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    scripts = node.verdicts(tx, (parent,), timeout_us=10_000, **context)
    node_ms = (perf_counter() - start) * 1000
    admission = submit_and_mine(node, tx)
    if scripts != [expected] or chain_ok != expected or admission["mined"] != expected or admission["mempool"] != expected:
        raise ValueError(f"unexpected verifier verdict: BSV {scripts}, chain-gang {chain_error}, {admission}")
    return {"raw": tx.serialize().hex(), "node_scripts": scripts, "node_rpc_ms": node_ms, "admission": admission,
            "chain_gang": chain_ok, "chain_gang_ms": chain_ms, "chain_gang_error": chain_error}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--runar", type=Path, required=True)
    cli.add_argument("--source", type=Path, default=SOURCE, help="Forth source for the generated circuit")
    cli.add_argument("--entries", nargs=2, metavar=("TRANSITION", "ROUTE"), help="select two Forth words")
    cli.add_argument("--go", default="go")
    cli.add_argument("--tx-version", type=int, choices=(1, 2), default=2)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    try:
        source = args.source.read_bytes()
        program = select_circuit(SourceCompiler(source.decode(), source_path=args.source), args.entries)
        circuit_source = emit_circuit(program)
    except (OSError, ValueError) as error:
        cli.error(f"{args.source}: {error}")
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("Groth16 replay needs the height-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("Groth16 replay requires an empty peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    keys = TestKeys()
    owner = keys.public["operator"]

    with TemporaryDirectory(prefix="4thgraph-groth16-replay-") as temporary:
        adapter = Path(temporary) / "adapter"
        build_adapter(args.runar, adapter, go=args.go)
        circuit = CircuitFixture(circuit_source, temporary, has_route=True)
        key = demo_keys(circuit)
        verifier = ScriptVerifier(adapter, key, temporary)
        # These are fixed statement data; the owner's signature covers the actual spend.
        signals, proof = prove(circuit, program, (1 << 32) - 1, (1, 2), "wrap")
        other_signals, other_proof = prove(circuit, program, 19, (1, 2), "other")
        lock = verifier.compile(signals, owner)
        witness = verifier.witness(signals, proof)
        wrong_statement = verifier.witness(other_signals, other_proof)
        tail = int(runar_proof(proof)["C"][1])
        if not witness.endswith(number(tail)):
            raise ValueError("unexpected final proof coordinate in witness")
        wrong_point = witness[:-len(number(tail))] + number(-tail % BASE_FIELD)

        native, bootstrap = fund(node, args.tx_version)
        deployment = Transaction((Input(bootstrap.txid_wire(), 0),), (Output(LOCK_VALUE, lock),), version=args.tx_version)
        deployment = native.unlock(deployment, 0, bootstrap, FLAG, None)
        deploy = submit_and_mine(node, deployment)
        if not deploy["mined"]:
            raise ValueError(f"could not deploy verifier: {deploy}")
        tx = Transaction((Input(deployment.txid_wire(), 0),), (Output(LOCK_VALUE - SPEND_FEE, native.output.script),),
                         version=args.tx_version)
        valid = sign_spend(tx, deployment, witness, keys)
        invalid = {
            "valid_proof_for_another_statement": sign_spend(tx, deployment, wrong_statement, keys),
            "negated_proof_point": sign_spend(tx, deployment, wrong_point, keys),
            "wrong_sighash": sign_spend(tx, deployment, witness, keys, flag=FORKID | SIGHASH_NONE),
            "changed_output_with_stale_signature": replace(
                valid, outputs=(replace(valid.outputs[0], value=tx.outputs[0].value - 1),),
            ),
        }
        controls = {name: verify_spend(node, activation, spend, deployment, deploy["height"], expected=False)
                    for name, spend in invalid.items()}
        active = deploy["height"] >= activation
        result = verify_spend(node, activation, valid, deployment, deploy["height"], expected=active)
        if not active and "disabled opcode" not in result["admission"].get("rpc_message", ""):
            raise ValueError("pre-Chronicle verifier did not fail on the expected disabled opcode")
        report = {
            "setup": "local-test-only", "bsv_node_version": node.version, "chain_gang": engine,
            "activation_height": activation, "regtest_profile": os.environ.get("SCRIPT_LAB_REGTEST_PROFILE"),
            "transaction_version": args.tx_version, "expected_spend": active,
            "forth_source_sha256": sha256(source).hexdigest(), "forth_circuit": program.describe(),
            "circuit": circuit.describe(),
            "verification_key": json.loads(key), "artifact": verifier.artifact(signals, owner, lock),
            "proof": json.loads(proof), "other_proof": json.loads(other_proof), "other_public_signals": other_signals,
            "witness_bytes": len(witness), "bootstrap_raw": bootstrap.serialize().hex(),
            "deployment_raw": deployment.serialize().hex(), "deployment": deploy, "spend": result, "controls": controls,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

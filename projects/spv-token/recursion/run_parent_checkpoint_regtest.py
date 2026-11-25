"""Spend a real parent with an authenticated SHA-256 checkpoint on isolated BSV regtest."""
import argparse
import json
from pathlib import Path

from checkpoint_verifier import DOMAIN, statement_bytes, verifier_lock, verifier_material
from parent_prefix import checkpoint_record
from statement_prover import StatementProver, add_prover_arguments
from regtest_support import Regtest
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction


def run(node, prover, out):
    if node.node.call("getconnectioncount") != 0:
        raise ValueError("use an isolated BSV regtest")
    setup = node.setup(outputs=3)
    parent_outputs = (Output(1000, asm("OP_1")), Output(2000, asm("OP_1")))
    parents = []
    for index, label in enumerate(("parent", "alternate-parent")):
        source = node.include(
            f"{label}-funding",
            Transaction((Input(setup.txid_wire(), index),), (Output(100_000, asm("OP_DROP OP_1")),)),
            (setup,),
        )
        signed = Transaction((Input(source.txid_wire(), 0, push(bytes(range(256)))),), parent_outputs)
        parents.append(node.include(label, signed, (source,)))
    parent, alternate = parents
    raw = parent.serialize()
    checkpoint = checkpoint_record(raw)
    with (out / "parent-checkpoint.json").open("x") as file:
        json.dump(checkpoint, file, indent=2)
        file.write("\n")
    (out / "parent.hex").write_text(raw.hex() + "\n")
    state, suffix = (bytes.fromhex(checkpoint[field]) for field in ("midstate", "suffix"))

    lock = verifier_lock(prover.key, required_output=parent_outputs[0])
    funded = Output(1_000_000, lock)
    funding = node.include("verifier-funding", Transaction((Input(setup.txid_wire(), 2),), (funded,)), (setup,))
    public_statement = statement_bytes(parent.txid_wire(), state, suffix)
    proof, evidence = prover.prove(public_statement, out / "checkpoint-proof.json", parent=list(raw))

    def candidate(previous, vout, disclosed_state, disclosed_suffix):
        draft = Transaction((Input(previous.txid_wire(), vout), Input(funding.txid_wire(), 0)),
                            (parent_outputs[0],))
        witness = proof + verifier_material(draft, funding, disclosed_state, disclosed_suffix)
        return draft.with_script(1, witness)

    cases = (
        ("wrong-midstate", parent, 0, bytes([state[0] ^ 1]) + state[1:], suffix),
        ("wrong-suffix", parent, 0, state, suffix[:-1] + bytes([suffix[-1] ^ 1])),
        ("other-parent-outpoint", alternate, 0, state, suffix),
        ("other-output-slot", parent, 1, state, suffix),
    )
    rejections = {}
    for label, *arguments in cases:
        rejected = candidate(*arguments)
        rejections[label] = {"txid": rejected.txid(), "rejection": node.reject(rejected)}
    signed = candidate(parent, 0, state, suffix)
    node.include("checkpoint-spend", signed, (parent, funding))
    if node.node.call("gettxout", parent.txid(), 0, False) is not None:
        raise AssertionError("checkpoint spend did not consume the real selected parent output")
    if node.node.call("gettxout", parent.txid(), 1, False) is None:
        raise AssertionError("the other parent output should retain its independent UTXO")
    return {
        "scope": "Two-output test parent authenticated by a separate plain Groth16 checkpoint input",
        "checkpoint": checkpoint, "verifying_key_sha256": prover.key_digest, "proof": evidence, "rejections": rejections,
        "parent_disclosure_bytes": len(state) + len(suffix),
        "parent_disclosure_with_encoding_bytes": len(push(state)) + len(push(suffix)),
        "raw_parent_with_encoding_bytes": len(push(raw)),
        "proof_witness_bytes": len(proof), "verifier_lock_bytes": len(lock),
        "verifier_funding_transaction_bytes": len(funding.serialize()),
        "checkpoint_spend_witness_bytes": len(signed.inputs[1].script),
        "node_timings": node.confirmation_timings["checkpoint-spend"],
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    add_prover_arguments(parser)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir()
    prover = StatementProver(args.zkey, args.wasm, args.ntt_shader, DOMAIN)
    result = run(Regtest(args.node_url, args.cookie), prover, args.out)
    with (args.out / "summary.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

"""Prepare two distinct CCTP split proofs and a candidate MIMO statement."""

import argparse
from importlib.util import find_spec
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic

from circom_fixture_prover import CompiledProver, export_artifacts
from ecdsa import SECP256k1, SigningKey
from regtest_mint import authorization
from shared.script import push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from split_relation_circuit import circuit_source
from statement import AssetDescriptor, Slot, TRANSFER_DOMAIN, public_inputs
from transaction_relation import TokenState, bind_transfer, token_lock
from transaction_verifier import verifier_key_id, verifier_lock, verifier_witness
from transfer import COMPACT_SCRIPTCODE


def prepare(build, issuance_anchor):
    source = build / "actual_split.circom"
    source.write_text(circuit_source())
    started = monotonic()
    subprocess.run(["circom", source, "--prime", "bls12381", "--r1cs", "--wasm", "-o", build], check=True)
    compile_seconds = monotonic() - started
    prover = CompiledProver.load(build / "actual_split.r1cs")
    key_id = verifier_key_id(prover.key)
    asset = AssetDescriptor(1, issuance_anchor, 6, 7, b"a" * 32, b"p" * 32)
    lock = verifier_lock(asset, prover.key)
    signer = SigningKey.from_secret_exponent(11, curve=SECP256k1)  # Test-only.
    owner = signer.verifying_key.to_string("compressed")
    has_engine = find_spec("tx_engine") is not None

    def token(quantity):
        return Output(20_000, token_lock(TokenState(asset.asset_id(), quantity, owner), lock))

    def verifier_funding(label):
        return Transaction((Input(hash256(label), 0),), (Output(20_000, lock),))

    parents = []
    proof_records = []
    for index, quantities in enumerate([(640, 384), (700, 324)]):
        verifier = verifier_funding(f"split-verifier-{index}".encode())
        token_parent = Transaction((Input(hash256(f"test-token-{index}".encode()), 0),), (token(1024),))
        tx = Transaction((Input(verifier.txid_wire(), 0), Input(token_parent.txid_wire(), 0)),
                         tuple(token(q) for q in quantities))
        input_slots = (Slot(1, 1024),)
        output_slots = tuple(Slot(i, q) for i, q in enumerate(quantities))
        bound = bind_transfer(asset, key_id, tx, (verifier.serialize(), token_parent.serialize()),
                              lock, input_slots, output_slots,
                              authenticated_preimage=preimage_all(tx, 0, 20_000, COMPACT_SCRIPTCODE))
        expected = public_inputs(bound.statement)
        witness_file = build / "witness.json"
        raw = bound.statement[len(TRANSFER_DOMAIN):]
        witness_file.write_text(json.dumps({
            "prefix": list(raw[:64]),
            "inputSlots": [list(raw[98:110])],
            "outputSlots": [list(raw[112:124]), list(raw[124:136])],
            "preimage": list(bound.preimage),
            "parent": list(token_parent.serialize()),
            "prevouts": list(bound.prevouts),
            "outputs": list(bound.outputs),
            "digestHigh": str(expected[0]),
            "digestLow": str(expected[1]),
        }))
        generated = build / "actual_split_js"
        started = monotonic()
        subprocess.run(["node", generated / "generate_witness.js", generated / "actual_split.wasm",
                        witness_file, build / "witness.wtns"], check=True)
        signals, proof = prover.prove(build / "witness.wtns")
        if signals != expected:
            raise ValueError("split proof does not represent the parent statement")
        vk, proof_json, signals_json = export_artifacts(prover.key, signals, proof)
        verifier_unlock = verifier_witness(asset, prover.key, proof, tx, verifier, input_slots, output_slots)
        token_preimage = preimage_all(tx, 1, 20_000, token_parent.outputs[0].script)
        token_unlock = (push(authorization(signer, token_preimage)) + push(verifier.serialize())
                        + push(bound.prevouts) + push(token_preimage))
        signed = tx.with_script(0, verifier_unlock).with_script(1, token_unlock)
        if has_engine:
            from shared.chain_gang import validate_at_heights

            validate_at_heights(signed, (verifier, token_parent), spend_height=100,
                                activation_height=2, utxo_heights=(3, 3))
        parents.append(signed)
        proof_records.append({"proof": proof_json, "signals": signals_json,
                              "statement": bound.statement.hex(),
                              "txid": signed.txid(),
                              "seconds": round(monotonic() - started, 3)})

    funding = verifier_funding(b"mimo-verifier")
    tx = Transaction((Input(funding.txid_wire(), 0), Input(parents[0].txid_wire(), 0),
                      Input(parents[1].txid_wire(), 1)), (token(700), token(264)))
    bound = bind_transfer(asset, key_id, tx, (funding.serialize(), *(p.serialize() for p in parents)),
                          lock, (Slot(1, 640), Slot(2, 324)), (Slot(0, 700), Slot(1, 264)),
                          authenticated_preimage=preimage_all(tx, 0, 20_000, COMPACT_SCRIPTCODE))
    return {"inner_vk": vk, "parents": proof_records, "context": hash256(bound.statement).hex(),
            "context_statement": bound.statement.hex(), "chain_gang_validated": has_engine,
            "inner_constraints": len(prover.rows),
            "inner_compile_seconds": round(compile_seconds, 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--issuance-anchor", type=bytes.fromhex, default=bytes(range(36)),
                        help="alternate 36-byte issuance outpoint in wire order, encoded as hex")
    args = parser.parse_args()
    if len(args.issuance_anchor) != 36:
        parser.error("expected a 36-byte issuance anchor")
    # Circom resolves existing absolute includes from the worktree.
    with TemporaryDirectory(prefix="cctp-recursion-") as tmp:
        prepared = prepare(Path(tmp), args.issuance_anchor)
    args.output.write_text(json.dumps(prepared, indent=2) + "\n")


if __name__ == "__main__":
    main()

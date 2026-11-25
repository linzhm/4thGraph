"""Measure independently funded verifier authentication with a real Groth16 proof."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

from funding_checkpoint import from_funding, statement_script
from public_inputs import verification_key_point
from run_covenant_backtrace_regtest import save
from run_inventory_wide_regtest import test_signer
from run_recursive_mimo import Regtest
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from snarkjs_adapter import load_artifacts
from transfer import COMPACT_SCRIPTCODE, compact_verifier_binding, shared_guard_lock, verifier_input_guard
from verifier import locking_script, unlocking_fields, unlocking_script


def p2pk(owner):
    return push(owner) + asm("OP_CHECKSIG")


def approve(tx, vin, previous, signer):
    digest = hash256(preimage_all(tx, vin, previous.value, previous.script))
    return push(signer(digest) + b"\x41")


def payment(verifier, guard, holders, witness, owner, signers, *, wrong_proof=False, checkpoint=None):
    parents = (verifier, guard, *holders)
    tx = Transaction(tuple(Input(parent.txid_wire(), 0) for parent in parents),
                     (Output(1_000, p2pk(owner)),) * 2, version=2)
    prevouts = b"".join(item.outpoint() for item in tx.inputs)

    def bind(vin, parent):
        spent = parents[vin].outputs[0]
        return (push(parent.serialize()) + push(prevouts)
                + push(preimage_all(tx, vin, spent.value, spent.script)))

    tx = tx.with_script(0, asm("OP_0") + witness[1 + witness[0]:] if wrong_proof else witness)
    if checkpoint is None:
        companion_witness = bind(1, verifier)
    else:
        preimage = preimage_all(tx, 1, guard.outputs[0].value, COMPACT_SCRIPTCODE)
        companion_witness = push(checkpoint.encode()) + push(prevouts) + push(preimage)
    tx = tx.with_script(1, companion_witness)
    for vin, sign in enumerate(signers, 2):
        tx = tx.with_script(vin, approve(tx, vin, parents[vin].outputs[0], sign) + bind(vin, guard))
    return tx


def run(node, key, public, proof, *, pinned_checkpoint_control=False):
    if node.node.call("getconnectioncount") != 0 or node.node.call("getblockcount") != 0:
        raise ValueError("use a fresh isolated BSV regtest with Chronicle at height 2")
    verifier = (number(public[0]) + number(public[1])
                + locking_script(key, None, projective_g1=True, projective_g2=True, reuse_constants=True)[0])
    guard = shared_guard_lock(verifier)
    point = verification_key_point(key.ic, public) or (0, 0)
    witness = unlocking_script((*point, *unlocking_fields(key, public, proof, projective_g1=True, projective_g2=True)))
    if not 1 <= witness[0] <= 75:
        raise ValueError("expected a short proof field push")
    alice, sign_alice = test_signer(21)
    bob, sign_bob = test_signer(22)
    setup = node.setup(outputs=3 if pinned_checkpoint_control else 2, anchor_tag=b"BSV/CCTP/open-verifier-funding/v1")
    ordinary = node.include("wallet-coins", Transaction((Input(setup.txid_wire(), 0),),
                            (Output(1_000_000, p2pk(alice)),) * 4 + (Output(1_000_000, p2pk(bob)),) * 4),
                            (setup,))

    def fund(label, source, vout, out, sign):
        tx = Transaction((Input(source.txid_wire(), vout),), (out,), version=1)
        return node.include(label, tx.with_script(0, approve(tx, 0, source.outputs[vout], sign)), (source,))

    confirmations = []
    rejects = {}
    for label, offset, owner, signer in (("alice", 0, alice, sign_alice), ("bob", 4, bob, sign_bob)):
        # Both locks and both holder signatures are independent of the funding
        # identities. Each payer signs only their own ordinary wallet coins.
        v = fund(f"{label}-verifier", ordinary, offset, Output(400_000, verifier), signer)
        checkpoint = None
        if pinned_checkpoint_control:
            checkpoint, lock_hash = from_funding(v.serialize())
            expected = checkpoint.digest(Input(v.txid_wire(), 0).outpoint(), lock_hash)
            guard = statement_script(lock_hash) + push(expected) + asm("OP_EQUAL") + compact_verifier_binding()
        g = fund(f"{label}-guard", ordinary, offset + 1, Output(300_000, guard), signer)
        holder = verifier_input_guard(guard, input_index=1) + p2pk(owner)
        holders = tuple(fund(f"{label}-holder-{i}", ordinary, offset + i, Output(2_000, holder), signer)
                        for i in (2, 3))
        if label == "alice":
            false_v = node.include("different-verifier", Transaction((Input(setup.txid_wire(), 1),),
                                   (Output(900_000, asm("OP_1")),), version=1), (setup,))
            rejects["different_verifier"] = node.reject(
                payment(false_v, g, holders, b"", owner, (signer, signer), checkpoint=checkpoint))
            rejects["different_guard"] = node.reject(
                payment(v, false_v, holders, witness, owner, (signer, signer), checkpoint=checkpoint))
            rejects["different_holder"] = node.reject(
                payment(v, g, holders, witness, owner, (sign_bob, signer), checkpoint=checkpoint))
            rejects["different_proof"] = node.reject(
                payment(v, g, holders, witness, owner, (signer, signer), wrong_proof=True, checkpoint=checkpoint))
            if checkpoint is not None:
                same_lock = node.include("same-lock-different-outpoint", Transaction((Input(setup.txid_wire(), 2),),
                                         (v.outputs[0],), version=1), (setup,))
                rejects["same_lock_different_outpoint"] = node.reject(
                    payment(same_lock, g, holders, witness, owner, (signer, signer), checkpoint=checkpoint))
                modified = replace(checkpoint, state=bytes([checkpoint.state[0] ^ 1]) + checkpoint.state[1:])
                rejects["different_midstate"] = node.reject(
                    payment(v, g, holders, witness, owner, (signer, signer), checkpoint=modified))
        tx = node.include(f"{label}-probe", payment(v, g, holders, witness, owner, (signer, signer),
                                                  checkpoint=checkpoint),
                          (v, g, *holders))
        payment_bytes = len(tx.serialize())
        confirmations.append({
            "payer": owner.hex(), "txid": tx.txid(), "verifier_outpoint": f"{v.txid()}:0",
            "guard_outpoint": f"{g.txid()}:0", "payment_bytes": payment_bytes,
            "verifier_funding_bytes": len(v.serialize()), "guard_funding_bytes": len(g.serialize()),
            "payment_and_funding_bytes": payment_bytes + len(v.serialize()) + len(g.serialize()),
            "input_witness_bytes": [len(item.script) for item in tx.inputs],
            "funding_transaction_bytes_in_guard_witness": len(v.serialize()) if checkpoint is None else 0,
            "checkpoint_disclosure_bytes": 0 if checkpoint is None else len(checkpoint.encode()),
        })
    return {
        "scope": ("Script binding control with one literal checkpoint digest per funding output. "
                  "No on-chain checkpoint proof verification or token lineage."
                  if pinned_checkpoint_control else
                  "Funding authentication component with a real fixed-statement Groth16 proof. No token lineage."),
        "verifier_lock_sha256": sha256(verifier).hexdigest(),
        "verifier_lock_bytes": len(verifier), "guard_lock_bytes": len(guard),
        "confirmations": confirmations, "rejections": rejects, "confirmation_timings": node.confirmation_timings,
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pinned-checkpoint-control", action="store_true",
                        help="test native transaction binding using one literal checkpoint digest per companion")
    args = parser.parse_args()
    artifact = json.loads(args.proof.read_text())
    key, public, proof = load_artifacts(artifact, artifact, artifact["public_signals"])
    save(args.out, run(Regtest(args.node_url, args.cookie), key, public, proof,
                      pinned_checkpoint_control=args.pinned_checkpoint_control))


if __name__ == "__main__":
    main()

"""Measure freeze and unfreeze with one reusable verifier lock at vin 1."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import freeze_split_token
from run_freeze_probe_regtest import prove_candidate, read_key
from run_recursive_mimo import Regtest
from shared.transaction import Input, Output, Transaction, preimage_all
from statement import AssetDescriptor
from statement_receipt import verifier_lock, verifier_material
from transaction_relation import TokenState
from transfer import COMPACT_SCRIPTCODE
from usdc_amount import USDC_DECIMALS


def _complete(tx, previous, funding, signer, proof_prefix):
    tx = replace(tx, outputs=(tx.outputs[0], freeze_split_token.receipt_output(tx, previous)))
    token_unlock = freeze_split_token.transaction_witness(tx, previous, funding, signer)
    verifier_unlock = proof_prefix + verifier_material(tx, funding)
    return tx.with_script(0, token_unlock).with_script(1, verifier_unlock)


def run(node, binary, parameters, output):
    if node.node.call("getconnectioncount") != 0:
        raise ValueError("use an isolated BSV regtest")
    from test_operational_token import fixture_signer

    _, sign = fixture_signer(12)
    manifest = json.loads((parameters / "manifest.json").read_text())
    if manifest["test_only"] is not True:
        raise ValueError("the isolated fixture requires test parameters")
    key, commitment = read_key(json.loads((parameters / "key.json").read_text()), manifest["profile"])
    proof_lock = verifier_lock(key, commitment)
    setup = node.setup(outputs=3)
    anchor = Input(setup.txid_wire(), 0)
    asset = AssetDescriptor(1, anchor.outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    initial = TokenState(asset.asset_id(), 640, node.owner_key)
    token_lock = freeze_split_token.lock(initial, node.freeze_key, proof_lock)
    issued = node.include("test-origin", Transaction((anchor,), (Output(1000, token_lock),)), (setup,))
    sponsor = Output(1_000_000, proof_lock)
    stages = {}
    parent = issued
    for index, label in enumerate(("freeze", "unfreeze"), 1):
        funding = node.include(f"verifier-funding-{label}", Transaction(
            (Input(setup.txid_wire(), index),), (sponsor,),
        ), (setup,))
        prev = parent.outputs[0]
        tx = Transaction((Input(parent.txid_wire(), 0), Input(funding.txid_wire(), 0)),
                         (freeze_split_token.paired_successor(prev),))
        if freeze_split_token.statement(tx, prev) != freeze_split_token.statement(
            replace(tx, outputs=(*tx.outputs, freeze_split_token.receipt_output(tx, prev))), prev,
        ):
            raise AssertionError("adding the receipt changed the proof's public statement")
        proof, record = prove_candidate(binary, parameters, output / f"{label}-proof.json", tx, prev, manifest, key)
        if label == "freeze":
            # The test issuer and the receipt authenticate the changed candidate.
            # The independent verifier must reject the original proof for it.
            changed = replace(tx, outputs=(replace(tx.outputs[0], value=tx.outputs[0].value - 1),))
            wrong = _complete(changed, prev, funding, sign, proof)
            record["changed_pair_value"] = {"txid": wrong.txid(), "rejection": node.reject(wrong)}
        final = _complete(tx, prev, funding, sign, proof)
        parent = node.include(label, final, (parent, funding))
        if node.node.call("gettxout", funding.txid(), 0, False) is not None:
            raise AssertionError("verified spend did not consume the actual verifier UTXO")
        record.update(
            token_witness_bytes=len(final.inputs[0].script), verifier_witness_bytes=len(final.inputs[1].script),
            proof_witness_bytes=len(proof), verifier_funding_bytes=len(funding.serialize()),
            token_preimage_bytes=len(preimage_all(final, 0, prev.value, prev.script)),
            verifier_preimage_bytes=len(preimage_all(final, 1, sponsor.value, COMPACT_SCRIPTCODE)),
            fee_satoshis=sponsor.value, node_timings=node.confirmation_timings[label],
        )
        stages[label] = record
    actual = node.node.call("gettxout", parent.txid(), 0, False)
    if parent.outputs[0] != issued.outputs[0] or actual is None or actual["scriptPubKey"]["hex"] != token_lock.hex():
        raise AssertionError("unfreeze did not restore the exact active split token output")
    return {
        "scope": "Isolated issuer-only proof with separate verifier funding on Bitcoin SV regtest",
        "asset_id": asset.asset_id().hex(), "token_lock_bytes": len(token_lock), "verifier_lock_bytes": len(proof_lock),
        "verifier_lock_sha256": sha256(proof_lock).hexdigest(),
        "parameters": manifest, "proofs": stages, **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--parameters", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir()
    result = run(Regtest(args.node_url, args.cookie), args.prover, args.parameters, args.out)
    with (args.out / "summary.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

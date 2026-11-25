"""Evaluate one plain Groth16 conservation proof for two real token inputs."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import conservation_probe
from conservation_inputs import actual_token_inputs_material, actual_token_inputs_script
from operational_token import TokenPolicy, shared_guard_witness
from statement_prover import StatementProver, add_prover_arguments
from regtest_support import Regtest
from shared.script import push
from shared.transaction import Input, Output, Transaction, blob
from statement import AssetDescriptor
from statement_receipt import verifier_lock, verifier_material
from transaction_relation import TokenState
from usdc_amount import USDC_DECIMALS


SHAPE = dict(input_count=4, verifier_index=0, preceding_outputs=2)


def _complete(tx, parents, parent_material, previous, signers, funding, companion, policy, proof, *,
              compressed, prefunded=False):
    tx = replace(tx, outputs=(*tx.outputs, conservation_probe.receipt_output(tx, previous)))
    if compressed:
        from conservation_compact_companion import companion_witness
        verifier_unlock = proof + verifier_material(tx, funding, **SHAPE)
        companion_unlock = companion_witness(tx, funding, companion, parents)
    else:
        verifier_unlock = proof + parent_material + verifier_material(tx, funding, **SHAPE)
        if prefunded:
            companion_unlock = conservation_probe.prefunded_companion_witness(tx, companion)
        else:
            companion_unlock = shared_guard_witness(tx, policy, funding, companion)
    signed = tx.with_script(0, verifier_unlock).with_script(1, companion_unlock)
    for vin, signer in enumerate(signers, start=2):
        witness = conservation_probe.token_witness(tx, vin, previous, companion, signer)
        signed = signed.with_script(vin, witness)
    return signed


def _check_unapproved_verifier(node, tx, parents):
    """Check every real input before submitting the intentionally rejected transaction."""
    flags = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19, 20, 21))
    raw = tx.serialize().hex()
    requests = []
    for index, (parent, txin) in enumerate(zip(parents, tx.inputs, strict=True)):
        if parent.txid_wire() != txin.txid:
            raise AssertionError("negative case must provide the actual parent at every vin")
        output = parent.outputs[txin.vout]
        block = node.node.call("getrawtransaction", parent.txid(), True)["blockhash"]
        height = node.node.call("getblockheader", block, True)["height"]
        requests.append({
            "tx": raw, "n": index, "flags": flags, "reportflags": True,
            "txo": {"lock": output.script.hex(), "value": output.value, "height": height},
        })
    results = node.node.call("verifyscript", requests, False, 10000)
    if len(results) != len(requests) or any(row["flags"] & flags != flags for row in results):
        raise AssertionError("node did not check the requested inputs and flags")
    statuses = [row["result"] for row in results]
    if statuses != ["ok", "error", "ok", "ok"]:
        raise AssertionError(f"expected only the companion to reject, got {statuses}")
    return {"txid": tx.txid(), "vin_results": statuses, "rejection": node.reject(tx)}


def run(node, prover, out, *, transfers=2, compressed=False, prefunded=False):
    if node.node.call("getconnectioncount") != 0:
        raise ValueError("use an isolated BSV regtest")
    if compressed and prefunded:
        raise ValueError("the pre-funded experiment uses the raw parent verification profile")
    from test_operational_token import fixture_signer

    lock = verifier_lock(prover.key, **SHAPE)
    if compressed:
        from conservation_compact_companion import companion_lock as compact_companion_lock, companion_parent_material
        policy = None
        companion_lock = compact_companion_lock(lock)
    else:
        lock = actual_token_inputs_script() + lock
        policy = TokenPolicy((lock,), node.freeze_key, certified_admin=True, shared_ordinary_guard=True)
        companion_lock = policy.shared_guard_lock()
    setup = node.setup(outputs=2 + 2 * transfers + int(prefunded))
    sponsor = Output(1_000_000, lock)

    def fund(label, index, output):
        return node.include(label, Transaction((Input(setup.txid_wire(), index),), (output,)), (setup,))

    labels = ("distinct-parents", "same-parent-successors", *(
        f"same-parent-hop-{step}" for step in range(3, transfers + 1)
    ))
    verifier_funders = ()
    if prefunded:
        verifier_funders = tuple(
            fund(f"{label}-verifier-funding", 2 + 2 * step, sponsor) for step, label in enumerate(labels)
        )
        for funding in verifier_funders:
            actual = node.node.call("gettxout", funding.txid(), 0, False)
            if actual is None or actual["scriptPubKey"]["hex"] != lock.hex():
                raise AssertionError("approved verifier does not match the actual unspent funding output")
        companion_lock = conservation_probe.prefunded_companion_lock(
            tuple(Input(funding.txid_wire(), 0).outpoint() for funding in verifier_funders),
        )
    anchor = Input(setup.txid_wire(), 0)
    asset = AssetDescriptor(1, anchor.outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    asset_id = asset.asset_id()
    holders = tuple(fixture_signer(i) for i in (11, 15, 16, 17))

    def token_output(amount, sats, holder):
        state = TokenState(asset_id, amount, holders[holder][0])
        return Output(sats, conservation_probe.lock(state, companion_lock=companion_lock))

    origins = tuple(node.include(
        f"test-origin-{i}", Transaction((Input(setup.txid_wire(), i),), (token_output(q, 1000, i),)), (setup,),
    ) for i, q in enumerate((640, 384)))
    parents = tuple((item, 0) for item in origins)
    records = {}
    for step, label in enumerate(labels):
        outputs = ((625, 1000, 0), (399, 1000, 1)) if step % 2 else ((700, 900, 2), (324, 1100, 3))
        funding = (verifier_funders[step] if prefunded else
                   fund(f"{label}-verifier-funding", 2 + 2 * step, sponsor))
        companion_output = Output(10_000, companion_lock)
        companion = fund(f"{label}-companion-funding", 3 + 2 * step, companion_output)
        previous = tuple(tx.outputs[vout] for tx, vout in parents)
        tx = Transaction(
            (Input(funding.txid_wire(), 0), Input(companion.txid_wire(), 0),
             *(Input(parent.txid_wire(), vout) for parent, vout in parents)),
            tuple(token_output(*args) for args in outputs),
        )
        proof, record = prover.prove(conservation_probe.statement(tx, previous), out / f"{label}-proof.json")
        signers = tuple(holders[i][1] for i in (range(2, 4) if step % 2 else range(2)))
        material = (companion_parent_material(lock, companion_lock, parents) if compressed else
                    actual_token_inputs_material(parents, companion))
        if step == 0:
            changed = replace(tx, outputs=(token_output(701, 900, 2), tx.outputs[1]))
            changed = _complete(changed, parents, material, previous, signers, funding, companion, policy, proof,
                                compressed=compressed, prefunded=prefunded)
            record["changed_successor_quantity"] = {"txid": changed.txid(), "rejection": node.reject(changed)}
            if prefunded:
                foreign = fund("unapproved-verifier-funding", 2 + 2 * transfers, sponsor)
                substituted = replace(tx, inputs=(Input(foreign.txid_wire(), 0), *tx.inputs[1:]))
                foreign_proof, evidence = prover.prove(conservation_probe.statement(substituted, previous),
                                                        out / "unapproved-verifier-proof.json")
                substituted = _complete(substituted, parents, material, previous, signers, foreign, companion,
                                        policy, foreign_proof, compressed=False, prefunded=True)
                record["same_lock_unapproved_verifier"] = {
                    **evidence, "funding_txid": foreign.txid(),
                    **_check_unapproved_verifier(node, substituted, (foreign, companion, *(p for p, _ in parents))),
                }
        final = _complete(tx, parents, material, previous, signers, funding, companion, policy, proof,
                          compressed=compressed, prefunded=prefunded)
        node.include(label, final, (funding, companion, *(item[0] for item in parents)))
        for actual in final.inputs:
            if node.node.call("gettxout", actual.txid[::-1].hex(), actual.vout, False) is not None:
                raise AssertionError("mined conservation transfer did not consume the designated UTXO")
        funding_raw = funding.serialize()
        copies = sum(txin.script.count(funding_raw) for txin in final.inputs)
        if prefunded and copies:
            raise AssertionError("pre-funded transfer disclosed the current verifier funding transaction")
        record.update(
            token_parents=[{"txid": parent.txid(), "vout": vout} for parent, vout in parents],
            direct_parent_bytes=sum(len(item.serialize()) for item in {item.txid(): item for item, _ in parents}.values()),
            token_out_quantities=[item[0] for item in outputs], token_out_sats=[item[1] for item in outputs],
            proof_count=1, new_parent_binding_proofs=0, proof_witness_bytes=len(proof),
            witness_bytes=[len(txin.script) for txin in final.inputs],
            encoded_direct_parent_bytes=len(material) if compressed else len(material) - len(push(companion.serialize())),
            verifier_funding_copies_in_witnesses=copies,
            proof_funding_bytes=len(funding_raw), companion_funding_bytes=len(companion.serialize()),
            fee_satoshis=sponsor.value + companion_output.value, node_timings=node.confirmation_timings[label],
        )
        records[label] = record
        parents = ((final, 0), (final, 1))
    for tx, vout in parents:
        if node.node.call("gettxout", tx.txid(), vout, False) is None:
            raise AssertionError("confirmed second-level token successor is missing")
    return {
        "scope": "Isolated 2-to-2 conservation with independent test origins and one proof per payment",
        "parent_mode": "lossless dictionary" if compressed else "raw transaction", "transfer_count": transfers,
        **({"approved_verifiers": [{"txid": funding.txid(), "vout": 0} for funding in verifier_funders]}
           if prefunded else {}),
        "asset_id": asset_id.hex(), "verifying_key_sha256": prover.key_digest, "proofs": records,
        "token_lock_bytes": len(origins[0].outputs[0].script),
        "verifier_lock_bytes": len(lock), "companion_lock_bytes": len(companion_lock),
        "verifier_script_field_sha256": sha256(blob(lock)).hexdigest(),
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    add_prover_arguments(parser)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--transfers", type=int, choices=range(2, 9), default=2)
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument("--compressed-parents", action="store_true")
    profile.add_argument("--prefunded-verifiers", action="store_true")
    args = parser.parse_args()
    args.out.mkdir()
    prover = StatementProver(args.zkey, args.wasm, args.ntt_shader, conservation_probe.DOMAIN)
    result = run(Regtest(args.node_url, args.cookie), prover, args.out,
                 transfers=args.transfers, compressed=args.compressed_parents, prefunded=args.prefunded_verifiers)
    with (args.out / "summary.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

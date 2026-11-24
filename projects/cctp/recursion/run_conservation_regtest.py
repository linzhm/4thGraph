"""Evaluate one plain Groth16 conservation proof for two real token inputs."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import conservation_probe
from conservation_inputs import actual_token_inputs_material, actual_token_inputs_script
from operational_token import TokenPolicy, shared_guard_witness
from run_freeze_probe_regtest import prove_statement, read_key
from run_recursive_mimo import Regtest
from shared.script import push
from shared.transaction import Input, Output, Transaction, blob
from statement import AssetDescriptor
from statement_receipt import verifier_lock, verifier_material
from transaction_relation import TokenState
from usdc_amount import USDC_DECIMALS


SHAPE = dict(input_count=4, verifier_index=0, preceding_outputs=2)


def _complete(tx, parents, parent_material, previous, signers, funding, companion, policy, proof, *, compressed):
    tx = replace(tx, outputs=(*tx.outputs, conservation_probe.receipt_output(tx, previous)))
    if compressed:
        from conservation_compact_companion import companion_witness
        verifier_unlock = proof + verifier_material(tx, funding, **SHAPE)
        companion_unlock = companion_witness(tx, funding, companion, parents)
    else:
        verifier_unlock = proof + parent_material + verifier_material(tx, funding, **SHAPE)
        companion_unlock = shared_guard_witness(tx, policy, funding, companion)
    signed = tx.with_script(0, verifier_unlock).with_script(1, companion_unlock)
    for vin, signer in enumerate(signers, start=2):
        witness = conservation_probe.token_witness(tx, vin, previous, companion, signer)
        signed = signed.with_script(vin, witness)
    return signed


def run(node, binary, parameters, out, *, transfers=2, compressed=False):
    if node.node.call("getconnectioncount") != 0:
        raise ValueError("use an isolated BSV regtest")
    from test_operational_token import fixture_signer

    manifest = json.loads((parameters / "manifest.json").read_text())
    if manifest["test_only"] is not True or manifest["profile"] != "conservation" or manifest["commitments"] != 0:
        raise ValueError("expected the plain conservation test parameters")
    data = json.loads((parameters / "key.json").read_text())
    key, _ = read_key(data, "plain")
    lock = verifier_lock(key, **SHAPE)
    if compressed:
        from conservation_compact_companion import companion_lock as compact_companion_lock, companion_parent_material
        policy = None
        companion_lock = compact_companion_lock(lock)
    else:
        lock = actual_token_inputs_script() + lock
        policy = TokenPolicy((lock,), node.freeze_key, certified_admin=True, shared_ordinary_guard=True)
        companion_lock = policy.shared_guard_lock()
    setup = node.setup(outputs=2 + 2 * transfers)
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
    for step in range(transfers):
        label = ("distinct-parents", "same-parent-successors")[step] if step < 2 else f"same-parent-hop-{step + 1}"
        outputs = ((625, 1000, 0), (399, 1000, 1)) if step % 2 else ((700, 900, 2), (324, 1100, 3))
        funding_outputs = Output(1_000_000, lock), Output(10_000, companion_lock)
        funding, companion = tuple(node.include(
            f"{label}-{name}-funding",
            Transaction((Input(setup.txid_wire(), 2 + 2 * step + j),), (output,)), (setup,),
        ) for j, (name, output) in enumerate(zip(("verifier", "companion"), funding_outputs, strict=True)))
        previous = tuple(tx.outputs[vout] for tx, vout in parents)
        tx = Transaction(
            (Input(funding.txid_wire(), 0), Input(companion.txid_wire(), 0),
             *(Input(parent.txid_wire(), vout) for parent, vout in parents)),
            tuple(token_output(*args) for args in outputs),
        )
        proof, record = prove_statement(binary, parameters, out / f"{label}-proof.json",
                                        conservation_probe.statement(tx, previous), manifest, key)
        signers = tuple(holders[i][1] for i in (range(2, 4) if step % 2 else range(2)))
        material = (companion_parent_material(lock, companion_lock, parents) if compressed else
                    actual_token_inputs_material(parents, companion))
        if step == 0:
            changed = replace(tx, outputs=(token_output(701, 900, 2), tx.outputs[1]))
            changed = _complete(changed, parents, material, previous, signers, funding, companion, policy, proof,
                                compressed=compressed)
            record["changed_successor_quantity"] = {"txid": changed.txid(), "rejection": node.reject(changed)}
        final = _complete(tx, parents, material, previous, signers, funding, companion, policy, proof,
                          compressed=compressed)
        node.include(label, final, (funding, companion, *(item[0] for item in parents)))
        for actual in final.inputs:
            if node.node.call("gettxout", actual.txid[::-1].hex(), actual.vout, False) is not None:
                raise AssertionError("mined conservation transfer did not consume the designated UTXO")
        record.update(
            token_parents=[{"txid": parent.txid(), "vout": vout} for parent, vout in parents],
            direct_parent_bytes=sum(len(item.serialize()) for item in {item.txid(): item for item, _ in parents}.values()),
            token_out_quantities=[item[0] for item in outputs], token_out_sats=[item[1] for item in outputs],
            proof_count=1, new_parent_binding_proofs=0, proof_witness_bytes=len(proof),
            witness_bytes=[len(txin.script) for txin in final.inputs],
            encoded_direct_parent_bytes=len(material) if compressed else len(material) - len(push(companion.serialize())),
            verifier_funding_copies_in_witnesses=sum(txin.script.count(funding.serialize()) for txin in final.inputs),
            proof_funding_bytes=len(funding.serialize()), companion_funding_bytes=len(companion.serialize()),
            fee_satoshis=sum(item.value for item in funding_outputs), node_timings=node.confirmation_timings[label],
        )
        records[label] = record
        parents = ((final, 0), (final, 1))
    for tx, vout in parents:
        if node.node.call("gettxout", tx.txid(), vout, False) is None:
            raise AssertionError("confirmed second-level token successor is missing")
    return {
        "scope": "Isolated 2-to-2 conservation with independent test origins and one proof per payment",
        "parent_mode": "lossless dictionary" if compressed else "raw transaction", "transfer_count": transfers,
        "asset_id": asset_id.hex(), "parameters": manifest, "proofs": records,
        "token_lock_bytes": len(origins[0].outputs[0].script),
        "verifier_lock_bytes": len(lock), "companion_lock_bytes": len(companion_lock),
        "verifier_script_field_sha256": sha256(blob(lock)).hexdigest(),
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--parameters", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--transfers", type=int, choices=range(2, 9), default=2)
    parser.add_argument("--compressed-parents", action="store_true")
    args = parser.parse_args()
    args.out.mkdir()
    result = run(Regtest(args.node_url, args.cookie), args.prover, args.parameters, args.out,
                 transfers=args.transfers, compressed=args.compressed_parents)
    with (args.out / "summary.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

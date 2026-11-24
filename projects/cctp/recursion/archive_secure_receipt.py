"""Archive confirmed v3 wallet payments and reconstruct their proof and transaction byte counts."""
import argparse
from hashlib import sha256
import json
import lzma
from pathlib import Path
from types import SimpleNamespace

from continuity_chain_proof import _proof_coordinates, chain_prior_artifact
from regtest_mint import Node
from run_secure_receipt_regtest import verifier_for
from shared.script import number, push
from shared.transaction import Transaction, blob, hash256, preimage_all
from wallet_receipt import BlockInclusion

MINTS = ("alice-first-mint", "alice-second-mint", "bob-existing-mint")
PAYMENTS = ("alice-to-bob", "bob-to-carol")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture(node, directory, key_path):
    summary = json.loads((directory / "summary.json").read_text())
    records = summary["transactions"]
    transactions, blocks, inputs = {}, {}, set()
    for record in records.values():
        txid, block_hash = record["txid"], record["blockhash"]
        if block_hash not in blocks:
            block = node.call("getblock", block_hash, 1)
            require(node.call("getblockhash", record["height"]) == block_hash == block["hash"]
                    and block["height"] == record["height"] and block["confirmations"] > 0, "inactive block")
            blocks[block_hash] = {"height": block["height"], "tx": block["tx"],
                                  "header": node.call("getblockheader", block_hash, False)}
        raw = node.call("getrawtransaction", txid, False)
        tx = Transaction.parse(bytes.fromhex(raw))
        require(txid == tx.txid() and len(raw) == 2 * record["bytes"] and txid in blocks[block_hash]["tx"],
                "wrong transaction from node")
        transactions[txid] = raw
        inputs.update(item.txid[::-1].hex() for item in tx.inputs)
    for txid in sorted(inputs - transactions.keys()):
        raw = node.call("getrawtransaction", txid, False)
        require(Transaction.parse(bytes.fromhex(raw)).txid() == txid, "wrong external funding")
        transactions[txid] = raw
    for block_hash, block in blocks.items():
        require(node.call("getblockhash", block["height"]) == block_hash, "chain changed during capture")
    proofs = {label: (directory / f"{label}-proof.json").read_text() for label in (*MINTS, *PAYMENTS)}
    return {"key_json": key_path.read_text(), "proof_json": proofs, "summary": summary,
            "transactions": transactions, "blocks": blocks}


def witness_partition(script, parts):
    offset, sizes = 0, {}
    for name, wire in parts:
        require(script.startswith(wire, offset), f"wrong witness field {name}")
        sizes[name] = len(wire)
        offset += len(wire)
    require(offset == len(script), "incomplete witness partition")
    return sizes


def audit(archive):
    summary = archive["summary"]
    records = summary["transactions"]
    ledger = {txid: Transaction.parse(bytes.fromhex(raw)) for txid, raw in archive["transactions"].items()}
    require(all(tx.txid() == txid for txid, tx in ledger.items()), "txid differs from canonical raw bytes")
    for record in records.values():
        block = archive["blocks"][record["blockhash"]]
        txid = bytes.fromhex(record["txid"])[::-1]
        txids = [bytes.fromhex(x)[::-1] for x in block["tx"]]
        proof = BlockInclusion.from_block(bytes.fromhex(block["header"]), block["height"], txids, txids.index(txid))
        require(proof.block_hash()[::-1].hex() == record["blockhash"] and proof.height == record["height"]
                and len(ledger[record["txid"]].serialize()) == record["bytes"], "incorrect archived block evidence")

    key = json.loads(archive["key_json"])
    deployment_keys = SimpleNamespace(minter_key=bytes.fromhex(summary["mint_public_key"]),
                                      freeze_key=bytes.fromhex(summary["freeze_public_key"]))
    verifier = verifier_for(deployment_keys, ledger[records["setup"]["txid"]], key)
    require(verifier.key_digest.hex() == summary["continuity_key_digest"]
            and sha256(blob(verifier.lock)).hexdigest() == summary["verifier_lock_hash"]
            and verifier.asset.asset_id().hex() == summary["asset_id"]
            and verifier.asset.issuance_outpoint.hex() == summary["issuance_anchor"], "wrong deployment")
    payment_checks = dict(zip(PAYMENTS, summary["payments"], strict=True))
    proof_records, measurements, embedded = {}, {}, {}
    for label in (*MINTS, *PAYMENTS):
        creating_mint = label in MINTS
        tx = ledger[records[label]["txid"]]
        prev = [ledger[i.txid[::-1].hex()] for i in tx.inputs]
        vi = verifier.verifier_input_index(tx)
        funding = prev[vi]
        receipt, context = verifier.context(tx, funding)
        if creating_mint:
            parents = [prev[0]]
            supports = ([ledger[parents[0].inputs[1].txid[::-1].hex()]] if receipt.parents else [])
            verifier.validate_mint(tx, funding, parents[0], supports[0] if supports else None)
            details = summary["mint_proof_checks"][label]
        else:
            parents = prev[1:]
            require(len(parents) == len({i.txid for i in tx.inputs[1:]}) == 2, "expected two distinct token parents")
            supports = [ledger[p.inputs[verifier.verifier_input_index(p)].txid[::-1].hex()] for p in parents]
            verifier.validate(tx, funding, parents, supports)
            details = payment_checks[label]

        text = archive["proof_json"][label]
        artifact = json.loads(text)
        recovered = chain_prior_artifact(verifier, key, tx, funding)
        require(recovered == {k: v for k, v in artifact.items() if k != "continuity"}
                and sha256(text.encode()).hexdigest() == details["proof_sha256"]
                and recovered["public_signals"] == details["public_signals"], "native proof differs from real witness")
        digest = receipt.digest(verifier.asset.asset_id(), verifier.key_digest, context)
        expected = {"asset": verifier.asset.asset_id().hex(), "self_key_digest": verifier.key_digest.hex(),
                    "transaction_context": context.hex(), "count": len(receipt.parents),
                    "prior_digests": [p.hex() for p in receipt.parents] + ["00" * 32] * (2 - len(receipt.parents)),
                    "digest": digest.hex()}
        require(artifact["continuity"] == expected, "wrong proof transcript")
        script = tx.inputs[vi].script
        _, proof_size = _proof_coordinates(script)
        proof_records[label] = {"txid": tx.txid(), "verifier_vin": vi, "native_artifact_sha256": details["proof_sha256"],
                                "public_signals": recovered["public_signals"], "digest": digest.hex(),
                                "prior_digests": expected["prior_digests"][:len(receipt.parents)],
                                "groth16_encoded_witness_bytes": proof_size}
        outs = b"".join(o.serialize() for o in tx.outputs)
        prevouts = b"".join(i.outpoint() for i in tx.inputs)
        mode = (3 + len(receipt.parents)) if creating_mint else verifier.transfer_mode(tx)
        verifier_fields = [("groth16_encoded_witness", script[:proof_size]), ("verifier_funding", push(funding.serialize()))]
        verifier_fields.extend((f"prior_verifier_funding_{i}", push(p.serialize())) for i, p in enumerate(supports))
        verifier_fields.extend((f"direct_parent_{i}", push(p.serialize())) for i, p in enumerate(parents))
        verifier_fields.extend([("ordered_outputs", push(outs)), ("ordered_outpoints", push(prevouts)),
                                ("preimage", push(verifier.context_preimage(tx, funding, vi))), ("mode", number(mode))])
        parts = witness_partition(script, verifier_fields)
        direct = [len(p.serialize()) for p in parents]
        nested = sum(embedded.get(p.txid(), 0) for p in parents)
        embedded[tx.txid()] = sum(direct)
        if creating_mint:
            continue

        holder_fields, amounts_in = [], []
        for vin, p in enumerate(parents, 1):
            inp = tx.inputs[vin]
            spent = p.outputs[inp.vout]
            state = verifier.policy.parse(spent.script)
            require(state is not None and state.asset_id == verifier.asset.asset_id() and not state.frozen,
                    "wrong spent token")
            sig = inp.script[1:1 + inp.script[0]]
            require(sig[-1:] == b"\x41", "wrong holder sighash")
            holder_fields.append(witness_partition(inp.script, [
                ("signature", push(sig)), ("verifier_funding", push(funding.serialize())),
                ("ordered_outpoints", push(prevouts)), ("preimage", push(preimage_all(tx, vin, spent.value, spent.script))),
                ("ordinary_branch", number(0)),
            ]))
            amounts_in.append(state.quantity)
        amounts_out = [verifier.policy.parse(o.script).quantity for o in tx.outputs[:-1]]
        satoshis_in = [p.outputs[i.vout].value for p, i in zip(prev, tx.inputs, strict=True)]
        satoshis_out = [o.value for o in tx.outputs]
        witnesses = [len(i.script) for i in tx.inputs]
        framing = len(tx.serialize()) - sum(witnesses) - len(outs)
        package = len(tx.serialize()) + len(funding.serialize())
        require(sum(amounts_in) == sum(amounts_out) and sum(satoshis_in) >= sum(satoshis_out)
                and witnesses == details["input_witness_bytes"] and details["payment_and_verifier_funding_bytes"] == package,
                "incorrect payment accounting")
        measurements[label] = {"txid": tx.txid(), "token_input_outpoints_wire": [i.outpoint().hex() for i in tx.inputs[1:]],
                               "token_input_units": amounts_in, "token_output_units": amounts_out,
                               "input_satoshis": satoshis_in, "output_satoshis": satoshis_out,
                               "fee_satoshis": sum(satoshis_in) - sum(satoshis_out),
                               "input_script_bytes": witnesses, "verifier_script_fields_including_pushes": parts,
                               "holder_script_fields_including_pushes": holder_fields,
                               "output_vector_bytes": len(outs), "transaction_framing_bytes": framing,
                               "direct_token_parent_raw_bytes": direct,
                               "direct_token_parent_raw_bytes_total": sum(direct),
                               "nested_protocol_parent_raw_bytes_within_direct_total": nested,
                               "transaction_bytes": len(tx.serialize()), "dedicated_verifier_funding_bytes": len(funding.serialize()),
                               "package_bytes": package}
    first = measurements[PAYMENTS[0]]
    second = measurements[PAYMENTS[1]]
    expected_inputs = ((MINTS[0], 1), (MINTS[1], 1), (PAYMENTS[0], 0), (MINTS[2], 1))
    points = [bytes.fromhex(records[name]["txid"])[::-1].hex() + vout.to_bytes(4, "little").hex()
              for name, vout in expected_inputs]
    require(first["token_input_outpoints_wire"] + second["token_input_outpoints_wire"] == points, "wrong respend topology")
    return {"accounting": "Encoded field sizes include Script pushes. Raw history metrics omit pushes. "
                          "Nested protocol-parent raw bytes are already inside direct parents and must not be added. "
                          "The coinbase is included as external funding, outside the labeled transaction count.",
            "labeled_transactions": len(records), "archived_transactions": len(ledger), "key_sha256": sha256(
                archive["key_json"].encode()).hexdigest(), "verifier_lock_hash": summary["verifier_lock_hash"],
            "proofs": proof_records, "payments": measurements,
            "second_minus_first_bytes": {k: second[k] - first[k] for k in ("transaction_bytes", "package_bytes",
                                                                           "direct_token_parent_raw_bytes_total")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    create = commands.add_parser("capture")
    create.add_argument("--node-url", required=True)
    create.add_argument("--cookie", type=Path, required=True)
    create.add_argument("--run-dir", type=Path, required=True)
    create.add_argument("--key", type=Path, required=True)
    for p in (create, commands.add_parser("replay")):
        p.add_argument("--archive", type=Path, required=True)
        p.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "capture":
        data = capture(Node(args.node_url, args.cookie), args.run_dir, args.key)
    else:
        with lzma.open(args.archive, "rt") as source:
            data = json.load(source)
    report = audit(data)
    if args.mode == "capture":
        with lzma.open(args.archive, "xt", preset=3) as output:
            json.dump(data, output, separators=(",", ":"))
    with args.audit.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()

"""Replay each input role of mined inventory G/H/I payments with BSV Node verifyscript."""
import argparse
from dataclasses import replace
import json
from pathlib import Path

from inventory_payment import holder_authorization
from inventory_ticket import ticket_token_witness, ticket_witness
from regtest_mint import Node
from replay_inventory_guards import Replay
from run_inventory_wide_regtest import test_signer
from shared.script import push
from shared.transaction import preimage_all
from transfer import COMPACT_SCRIPTCODE


def verifier_tail(tx, sats):
    return (push(b"".join(i.outpoint() for i in tx.inputs))
            + push(preimage_all(tx, 0, sats, COMPACT_SCRIPTCODE)))


def replay_tickets(replay, profile):
    labels = ("payment-1", "payment-1-verifier", "payment-1-companion",
              "negative-same-verifier-lock", "negative-same-ticket-lock", "issuance-anchor")
    original, verifier, ticket, other_verifier, other_ticket, anchor = map(replay.actual, labels)
    if (original.inputs[0].txid != verifier.txid_wire() or original.inputs[1].txid != ticket.txid_wire()
            or original.inputs[0].vout or original.inputs[1].vout
            or verifier.outputs != other_verifier.outputs or ticket.outputs != other_ticket.outputs
            or verifier.txid() == other_verifier.txid() or ticket.txid() == other_ticket.txid()
            or any(f.inputs[0].txid != anchor.txid_wire() for f in (ticket, other_ticket))
            or (ticket.inputs[0].vout, other_ticket.inputs[0].vout) != (128, 133)):
        raise ValueError("unexpected verifier, ticket or coupon funding in archive")

    block_members = {}
    claimed_txids = {item.txid[::-1].hex() for item in original.inputs}
    claimed_txids.update(replay.records[label]["txid"] for label in labels)
    for txid in claimed_txids:
        record = replay.by_txid[txid]
        block = record["blockhash"]
        if block not in block_members:
            header = replay.node.call("getblock", block, 1)
            if header["height"] != record["height"] or header["confirmations"] < 1:
                raise ValueError("funding evidence refers to an inactive block or a different height")
            block_members[block] = set(header["tx"])
        if txid not in block_members[block]:
            raise ValueError("funding transaction absent from the archived confirming block")

    old_tail = verifier_tail(original, verifier.outputs[0].value)
    if not original.inputs[0].script.endswith(old_tail):
        raise ValueError("original verifier witness differs from the archived format")
    verifier_prefix = original.inputs[0].script[:-len(old_tail)]
    origin_labels = {r["txid"]: label for label, r in replay.records.items() if label.startswith("origin-")}
    holder_inputs = []
    for item in original.inputs[2:]:
        txid = item.txid[::-1].hex()
        previous = replay.by_id(txid).outputs[item.vout]
        owner = int(origin_labels[txid].removeprefix("origin-"))
        holder_inputs.append((previous, test_signer(1000 + owner)[1]))

    def reseal(verifier_funding, ticket_funding):
        inputs = (replace(original.inputs[0], txid=verifier_funding.txid_wire()),
                  replace(original.inputs[1], txid=ticket_funding.txid_wire()), *original.inputs[2:])
        tx = replace(original, inputs=inputs)
        signed = tx.with_script(0, verifier_prefix + verifier_tail(tx, verifier_funding.outputs[0].value))
        signed = signed.with_script(1, ticket_witness(tx, ticket_funding, test_signer(2020)[1]))
        for vin, (previous, owner_sign) in enumerate(holder_inputs, 2):
            if profile == "i":
                # Reuse the approved coupon fields of the mined witness. Keep both
                # signatures bound to the candidate, including its actual vin 0/1.
                sig, binding = holder_authorization(original, vin, previous, owner_sign, compact_holder=True)
                old = original.inputs[vin].script
                if not old.startswith(push(sig)) or not old.endswith(push(binding)):
                    raise ValueError("original holder witness differs from the archived format")
                fields = old[len(push(sig)):-len(push(binding))]
                sig, binding = holder_authorization(tx, vin, previous, owner_sign, compact_holder=True)
                witness = push(sig) + fields + push(binding)
            else:
                witness = ticket_token_witness(tx, vin, previous, ticket_funding, owner_sign,
                                               derive_prevouts=profile == "h")
            signed = signed.with_script(vin, witness)
        return signed

    variants = (
        ("mined_original", original, ("ok", "ok", "ok")),
        ("same_verifier_lock_other_txid", reseal(other_verifier, ticket), ("ok", "ok", "error")),
        ("ticket_from_unapproved_coupon", reseal(verifier, other_ticket), ("ok", "ok", "error")),
        ("wrong_ticket_signature", original.with_script(1, ticket_witness(original, ticket, test_signer(2021)[1])),
         ("ok", "error", "ok")),
    )
    checks = {label: replay.check(tx, (0, 1, 2), list(expected)) for label, tx, expected in variants}
    token = original.inputs[2]
    return {"mined": {label: replay.records[label] for label in (*labels, origin_labels[token.txid[::-1].hex()])},
            "holder_vin": 2, "holder_origin_vout": token.vout, "results": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).resolve().parents[1] / "fixtures")
    parser.add_argument("--profiles", choices=("g", "h", "i"), nargs="+", default=("g", "h", "i"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    node = Node(args.node_url, args.cookie)
    result = {"scope": "Read-only verifyscript of vin 0 (shared verifier), 1 (ticket), 2 (first holder) over "
                       "mined regtest inputs. Variants only replace the named outpoint or ticket signature. "
                       "Outpoint variants refresh the shared verifier, ticket and every holder witness. "
                       "Profile I supplies the approved ticket fields for both outpoint variants.",
              "node": node.call("getnetworkinfo")["subversion"],
              "profiles": {p: replay_tickets(Replay(node, args.fixtures, p), p) for p in args.profiles}}
    with args.out.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

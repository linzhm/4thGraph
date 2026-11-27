"""Inspect the pinned CCTP two-payment archive as a byte-checked CPN graph.

The archive contains transactions and recorded observations. This module checks
wire identities and selected relationships; it does not execute Script or
independently establish block inclusion, an unspent output, or asset validity.
"""

import argparse
from hashlib import sha256
import json
import lzma
from pathlib import Path

from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import Transaction


TOKEN_PREFIX = push(b"BSV/CCTP/covenant-token/v1\0") + asm("OP_DROP") + b"\x08"
OWNER_PREFIX = (
    asm("OP_DROP OP_DEPTH OP_3 OP_NUMEQUALVERIFY OP_ROT OP_SIZE 71 OP_NUMEQUALVERIFY "
        "OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
    + push(b"\x41") + asm("OP_EQUALVERIFY") + b"\x21"
)
QUANTITY_OFFSET = len(TOKEN_PREFIX)
OWNER_OFFSET = QUANTITY_OFFSET + 8 + len(OWNER_PREFIX)
ISSUANCE_AMOUNTS = (300, 200, 150)
PAYMENTS = ("alice-to-bob", "bob-to-carol")
MINTS = ("alice-mint-1", "alice-mint-2", "bob-mint")


def read_archive(path):
    raw = path.read_bytes()
    encoded = lzma.decompress(raw) if raw.startswith(b"\xfd7zXZ\0") else raw
    return json.loads(encoded), sha256(raw).hexdigest()


def inspect_archive(archive, *, archive_sha256=None, policy=None):
    """Return a finite graph whose places are actual serialized outpoints."""
    recorded_policy = archive["recipient_policy"]
    if policy is not None and policy != recorded_policy:
        raise ValueError("supplied policy differs from the archive")
    policy = recorded_policy if policy is None else policy
    records, raw_transactions = archive["summary"]["transactions"], archive["transactions"]
    names = ("issuance-root", "verifier-funding", *MINTS, *PAYMENTS)
    transactions = {}
    for name in names:
        record = records[name]
        tx = Transaction.parse(bytes.fromhex(raw_transactions[record["txid"]]))
        if tx.txid() != record["txid"] or len(tx.serialize()) != record["bytes"]:
            raise ValueError(f"{name}: transaction does not match its archived identity")
        transactions[name] = tx
    root, funding = transactions["issuance-root"], transactions["verifier-funding"]
    if root.txid() != policy["issuance_root"] or funding.txid() != policy["verifier_funding"]:
        raise ValueError("archive transaction identities differ from the stated policy")
    if len(root.outputs) != 3 or len(funding.outputs) != 2:
        raise ValueError("unsupported issuance or verifier funding shape")
    if any(sha256(output.script).hexdigest() != policy["verifier_lock_sha256"] for output in funding.outputs):
        raise ValueError("verifier funding script differs from the stated policy")

    # Fixed record layout from the archived CCTP covenant. All token outputs must
    # have the same complete script with only these two state fields substituted.
    funding_wire = funding.txid_wire()
    template = None

    def token_state(output):
        nonlocal template
        script = output.script
        if (output.value != 1000 or not script.startswith(TOKEN_PREFIX)
                or script[QUANTITY_OFFSET + 8:OWNER_OFFSET] != OWNER_PREFIX
                or len(script) < OWNER_OFFSET + 33):
            raise ValueError("output does not have the archived token layout")
        quantity = int.from_bytes(script[QUANTITY_OFFSET:QUANTITY_OFFSET + 8], "little")
        owner = script[OWNER_OFFSET:OWNER_OFFSET + 33]
        if quantity == 0 or owner[0] not in (2, 3) or script.count(funding_wire) != 1:
            raise ValueError("invalid token state or verifier-funding reference")
        normalized = (script[:QUANTITY_OFFSET] + bytes(8) + script[QUANTITY_OFFSET + 8:OWNER_OFFSET]
                      + bytes(33) + script[OWNER_OFFSET + 33:])
        if template is None:
            template = normalized
        elif normalized != template:
            raise ValueError("token locking scripts differ outside the state fields")
        return {"quantity": quantity, "owner_compressed": owner.hex(),
                "verifier_funding_txid": funding.txid()}

    places, transitions, edges = {}, [], []
    consumed = set()

    def check_consumption(tx, name):
        # This is the selected archive subgraph only: it detects conflicting
        # archived spends, but says nothing about spends outside the archive.
        for txin in tx.inputs:
            point = txin.outpoint()
            if point in consumed:
                raise ValueError(f"{name}: input outpoint is already consumed in this archive")
            consumed.add(point)

    def outpoint(txid, vout):
        return f"{txid}:{vout}"

    def place(tx, vout, kind):
        key = outpoint(tx.txid(), vout)
        output = tx.outputs[vout]
        row = {"id": key, "kind": kind, "satoshis": output.value,
               "script_bytes": len(output.script), "script_sha256": sha256(output.script).hexdigest()}
        if kind == "token":
            row["token"] = token_state(output)
        if key in places and places[key] != row:
            raise ValueError("same outpoint has inconsistent state")
        places[key] = row
        return key

    for slot, amount in enumerate(ISSUANCE_AMOUNTS):
        mint = transactions[MINTS[slot]]
        if len(mint.inputs) != 1 or len(mint.outputs) != 1 or mint.inputs[0].outpoint() != root.txid_wire() + slot.to_bytes(4, "little"):
            raise ValueError(f"{MINTS[slot]}: missing declared issuance anchor slot")
        check_consumption(mint, MINTS[slot])
        root_id, token_id = place(root, slot, "issuance-anchor"), place(mint, 0, "token")
        if places[token_id]["token"]["quantity"] != amount:
            raise ValueError(f"{MINTS[slot]}: quantity differs from declared issuance allowance")
        transitions.append({"id": MINTS[slot], "kind": "mint", "txid": mint.txid(),
                            "inputs": [root_id], "outputs": [token_id], "bytes": len(mint.serialize())})
        edges.extend([{"from": root_id, "to": MINTS[slot], "port": "vin:0"},
                      {"from": MINTS[slot], "to": token_id, "port": "vout:0"}])

    by_txid = {tx.txid_wire(): tx for tx in transactions.values()}
    funding_slots = set()
    for name in PAYMENTS:
        tx = transactions[name]
        if len(tx.inputs) != 3 or len(tx.outputs) != 2:
            raise ValueError(f"{name}: expected three inputs and two outputs")
        inputs = []
        for vin, txin in enumerate(tx.inputs):
            parent = by_txid.get(txin.txid)
            if parent is None or not 0 <= txin.vout < len(parent.outputs):
                raise ValueError(f"{name}: input {vin} has no matching archived parent output")
            if vin == 0:
                if parent.txid() != funding.txid() or txin.vout in funding_slots:
                    raise ValueError(f"{name}: wrong or repeated verifier funding outpoint")
                funding_slots.add(txin.vout)
            inputs.append(place(parent, txin.vout, "verifier-funding" if vin == 0 else "token"))
        if len(set(inputs)) != len(inputs):
            raise ValueError(f"{name}: duplicate input outpoint")
        check_consumption(tx, name)
        recorded_parents = archive["summary"]["payments"][name]["direct_token_parents"]
        if inputs[1:] != recorded_parents:
            raise ValueError(f"{name}: token inputs differ from the payment summary")
        outputs = [place(tx, vout, "token") for vout in range(len(tx.outputs))]
        if sum(places[key]["token"]["quantity"] for key in inputs[1:]) != sum(
                places[key]["token"]["quantity"] for key in outputs):
            raise ValueError(f"{name}: token quantities do not balance")
        transitions.append({"id": name, "kind": "transfer", "txid": tx.txid(), "inputs": inputs,
                            "outputs": outputs, "bytes": len(tx.serialize())})
        edges.extend({"from": key, "to": name, "port": f"vin:{vin}"} for vin, key in enumerate(inputs))
        edges.extend({"from": name, "to": key, "port": f"vout:{vout}"} for vout, key in enumerate(outputs))
    if transactions[PAYMENTS[1]].inputs[1].outpoint() != transactions[PAYMENTS[0]].txid_wire() + bytes(4):
        raise ValueError("second payment does not consume the first payment's first output")
    return {
        "schema_version": 1,
        "source": {"archive_sha256": archive_sha256, "policy_origin": "caller" if policy is not recorded_policy else "archive",
                   "issuance_root": root.txid(), "issuance_amounts": ISSUANCE_AMOUNTS,
                   "verifier_funding": funding.txid(), "verifier_lock_sha256": policy["verifier_lock_sha256"],
                   "verifying_key_sha256": policy["verifying_key_sha256"]},
        "validation": {"transaction_hashes_and_slots": "checked", "token_template": "marker and common bytes matched",
                       "unique_input_consumption": "checked within selected archive only",
                       "transaction_signatures": "not checked", "script_execution": "not checked",
                       "block_inclusion": "not checked", "unspent_status": "not checked",
                       "issuance_authorization": "policy asserted by archive or caller"},
        "places": list(places.values()), "transitions": transitions, "edges": edges,
    }


def logical_model(graph):
    """Convert the finite, byte-checked archive graph to logical CPN schema v1.

    Initial tokens represent the boundary of the archived subgraph. They do not
    assert that those outpoints are currently unspent or independently valid.
    """
    from fourthgraph.workflow.logical_cpn import validate_document

    kinds = {place["id"]: place["kind"] for place in graph["places"]}
    produced = {output for step in graph["transitions"] for output in step["outputs"]}
    places = []
    for item in graph["places"]:
        metadata = {
            "carrier": "archived-outpoint", "actual_outpoint": item["id"],
            "satoshis": item["satoshis"], "script_bytes": item["script_bytes"],
            "script_sha256": item["script_sha256"], "archive_validation": graph["validation"],
            "issuance_root": graph["source"]["issuance_root"],
        }
        if "token" in item:
            metadata["token"] = item["token"]
        places.append({"name": item["id"], "type": item["kind"], "initial": int(item["id"] not in produced),
                       "capacity": 1, "metadata": metadata})
    transitions = []
    for step in graph["transitions"]:
        inputs = [{"name": f"vin:{index}", "place": point, "type": kinds[point]}
                  for index, point in enumerate(step["inputs"])]
        outputs = [{"name": f"vout:{index}", "place": point, "type": kinds[point]}
                   for index, point in enumerate(step["outputs"])]
        transitions.append({"name": step["id"], "inputs": inputs, "outputs": outputs,
                            "metadata": {"kind": step["kind"], "actual_txid": step["txid"],
                                         "transaction_bytes": step["bytes"], "source": graph["source"],
                                         "archive_validation": graph["validation"]}})
    result = validate_document({"schema_version": 1, "places": places, "transitions": transitions})
    if not result["ok"]:
        raise ValueError(f"invalid logical CPN mapping: {result['diagnostics']}")
    return result["model"]


def flow_report(archive, *, archive_sha256=None, policy=None):
    """Check token quantities and outpoint handoff in the bounded archive graph.

    The graph starts at its explicitly recorded boundary and follows the five
    archived transactions in order. This checks the bytes and the selected
    subgraph, without claiming chain validity or the current UTXO set.
    """
    graph = inspect_archive(archive, archive_sha256=archive_sha256, policy=policy)
    model = logical_model(graph)
    places = {place["name"]: place for place in model["places"]}
    live = {name for name, place in places.items() if place["initial"]}
    boundary = sorted(live)
    produced_by = {}
    steps, handoffs = [], []
    issued = 0

    def port_state(port):
        place = places[port["place"]]
        state = {"port": port["name"], "outpoint": port["place"], "kind": place["type"],
                 "satoshis": place["metadata"]["satoshis"],
                 "script_sha256": place["metadata"]["script_sha256"]}
        if "token" in place["metadata"]:
            state.update(place["metadata"]["token"])
        return state

    for transition in model["transitions"]:
        consumed = [arc["place"] for arc in transition["inputs"]]
        created = [arc["place"] for arc in transition["outputs"]]
        if any(point not in live for point in consumed):
            raise ValueError(f"{transition['name']}: input is missing or already consumed in this archive")
        if any(point in live or point in produced_by for point in created):
            raise ValueError(f"{transition['name']}: output repeats an archive outpoint")
        inputs, outputs = ([port_state(arc) for arc in side]
                           for side in (transition["inputs"], transition["outputs"]))
        token_inputs = [item for item in inputs if item["kind"] == "token"]
        token_outputs = [item for item in outputs if item["kind"] == "token"]
        incoming = sum(item["quantity"] for item in token_inputs)
        outgoing = sum(item["quantity"] for item in token_outputs)
        is_transfer = transition["metadata"]["kind"] == "transfer"
        if is_transfer and (len(token_inputs) != 2 or len(token_outputs) != 2 or incoming != outgoing):
            raise ValueError(f"{transition['name']}: archived 2-to-2 token quantities do not balance")
        if not is_transfer:
            issued += outgoing
        for item in token_inputs:
            predecessor = produced_by.get(item["outpoint"])
            if predecessor is not None:
                handoffs.append({"outpoint": item["outpoint"], "from": predecessor, "to": transition["name"],
                                 "input_port": item["port"], "quantity": item["quantity"],
                                 "owner_compressed": item["owner_compressed"]})
        live.difference_update(consumed)
        live.update(created)
        produced_by.update({point: transition["name"] for point in created})
        steps.append({"name": transition["name"], "kind": transition["metadata"]["kind"],
                      "txid": transition["metadata"]["actual_txid"], "inputs": inputs, "outputs": outputs,
                      "token_in": incoming, "token_out": outgoing,
                      "conservation": "checked" if is_transfer else "issuance"})

    remaining = [places[point] for point in sorted(live) if places[point]["type"] == "token"]
    remaining_quantity = sum(place["metadata"]["token"]["quantity"] for place in remaining)
    if issued != remaining_quantity:
        raise ValueError("selected archive graph does not conserve the issued token quantity")
    return {
        "schema_version": 1, "scope": "selected five archive transactions in order",
        "source": graph["source"], "validation": graph["validation"],
        "boundary": {"initial_outpoints": boundary,
                     "meaning": "selected graph inputs; current unspent status is not checked"},
        "steps": steps, "handoffs": handoffs,
        "invariants": {"issuance_slot_quantities": list(ISSUANCE_AMOUNTS),
                       "issued_token_quantity": issued, "remaining_token_quantity": remaining_quantity,
                       "conserved_within_selected_graph": True,
                       "unique_consumption_within_selected_graph": True},
        "remaining_outputs": [{"outpoint": place["name"], "satoshis": place["metadata"]["satoshis"],
                               **place["metadata"]["token"]} for place in remaining],
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("archive", type=Path, help="CCTP covenant-backtrace-2x2-regtest.json.xz or decoded JSON")
    cli.add_argument("--policy", type=Path, help="require an independently supplied recipient-policy JSON")
    output = cli.add_mutually_exclusive_group()
    output.add_argument("--logical", action="store_true", help="emit the typed logical CPN schema")
    output.add_argument("--flow-report", action="store_true", help="emit the bounded token flow and invariants")
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    try:
        archive, digest = read_archive(args.archive)
        policy = json.loads(args.policy.read_text()) if args.policy else None
        if args.flow_report:
            graph = flow_report(archive, archive_sha256=digest, policy=policy)
        else:
            graph = inspect_archive(archive, archive_sha256=digest, policy=policy)
            if args.logical:
                graph = logical_model(graph)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(graph, indent=2) + "\n")
    except (KeyError, IndexError, OSError, TypeError, ValueError, lzma.LZMAError) as error:
        cli.error(str(error))
    print(args.output)


if __name__ == "__main__":
    main()

"""Explicit logical-CPN interface to the pinned CCTP 2-to-2 test fixture."""

from dataclasses import replace
from hashlib import sha256

from fourthgraph.bsv.script import script_operations
from fourthgraph.bsv.transaction import Transaction
from fourthgraph.workflow.cctp_archive import PAYMENTS, inspect_archive, logical_model, read_archive
from fourthgraph.workflow.cctp_transfer_fixture import ARCHIVE_SHA256, construct_fixture_spend
from fourthgraph.workflow.logical_cpn import parse_net, validate_document


def _fixed_context(archive_path):
    archive, digest = read_archive(archive_path)
    if digest != ARCHIVE_SHA256:
        raise ValueError("this adapter requires the pinned CCTP test archive")
    graph = inspect_archive(archive, archive_sha256=digest)
    transfer = next(row for row in graph["transitions"] if row["id"] == PAYMENTS[0])
    tx = Transaction.parse(bytes.fromhex(archive["transactions"][transfer["txid"]]))
    operations = tuple(script_operations(tx.inputs[0].script))
    if len(operations) != 26 or any(len(item) != 49 or item[0] != 48 for item in operations[:22]):
        raise ValueError("archived verifier witness has an unexpected proof layout")
    places = {row["id"]: row for row in graph["places"]}
    selected = [places[point] for point in transfer["inputs"]]
    source = graph["source"]
    requirements = {
        "kind": "fixed-cctp-2x2-transfer",
        "constraints": [
            {"kind": "token-quantity-conservation"},
            {"kind": "ordered-input-outpoints"},
            {"kind": "ordered-token-outputs"},
        ],
        "authorization": [
            {"vin": vin, "owner_compressed": row["token"]["owner_compressed"]}
            for vin, row in enumerate(selected[1:], 1)
        ],
        "witnesses": [
            {"kind": "parent-opening-proof", "vin": 0},
            {"kind": "ordered-prevouts-and-preimage", "vin": 0},
            {"kind": "owner-signature-prevouts-and-preimage", "vin": 1},
            {"kind": "owner-signature-prevouts-and-preimage", "vin": 2},
        ],
        "evidence": [{
            "kind": "fixed-parent-opening",
            "archive_sha256": digest,
            "issuance_root": source["issuance_root"],
            "verifier_funding": source["verifier_funding"],
            "verifier_lock_sha256": source["verifier_lock_sha256"],
            "verifying_key_sha256": source["verifying_key_sha256"],
            "proof_sha256": sha256(b"".join(operations[:22])).hexdigest(),
            "proof_inputs_sha256": sha256(operations[-3]).hexdigest(),
        }],
    }
    return graph, selected, requirements


def fixture_declaration(archive_path):
    """Create an explicit fixed-parent transition with symbolic output places."""
    _, inputs, requirements = _fixed_context(archive_path)
    places = []
    for name, source in zip(("funding", "token-a", "token-b"), inputs, strict=True):
        metadata = {"carrier": "archived-outpoint", "actual_outpoint": source["id"],
                    "satoshis": source["satoshis"], "script_sha256": source["script_sha256"]}
        if "token" in source:
            metadata["token"] = source["token"]
        places.append({"name": name, "type": source["kind"], "initial": 1, "capacity": 1, "metadata": metadata})
    places.extend({"name": name, "type": "token", "initial": 0, "capacity": 1,
                   "metadata": {"carrier": "proposed-utxo"}} for name in ("output-a", "output-b"))
    transition = {
        "name": "transfer-2x2",
        "inputs": [{"name": f"vin:{i}", "place": place["name"], "type": place["type"]}
                   for i, place in enumerate(places[:3])],
        "outputs": [{"name": f"vout:{i}", "place": place["name"], "type": place["type"]}
                    for i, place in enumerate(places[3:])],
        "metadata": requirements,
    }
    return parse_net({"schema_version": 1, "places": places, "transitions": [transition]}).describe()


def construct_declared_fixture_spend(archive_path, declaration, payouts, signer):
    """Validate the entire declaration before invoking the external signer.

    The result is a signed proposed transaction over historical fixture parents.
    No live UTXO, mempool, block inclusion or independent proof check is implied.
    """
    actual = parse_net(declaration).describe()
    if len(actual["transitions"]) != 1 or len(actual["places"]) != 5:
        raise ValueError("expected exactly one fixed-parent transfer and five places")
    transition = actual["transitions"][0]
    incoming, outgoing = transition["inputs"], transition["outputs"]
    if len(incoming) != 3 or len(outgoing) != 2 or transition["word"] is not None:
        raise ValueError("expected three ordered input ports, two ordered output ports and no Forth word")
    names = [arc["place"] for arc in (*incoming, *outgoing)]
    if len(set(names)) != 5 or set(names) != {place["name"] for place in actual["places"]}:
        raise ValueError("each port must have a distinct declared place")
    if ([arc["name"] for arc in incoming] != ["vin:0", "vin:1", "vin:2"]
            or [arc["name"] for arc in outgoing] != ["vout:0", "vout:1"]
            or any(arc["count"] != 1 for arc in (*incoming, *outgoing))):
        raise ValueError("fixture requires exactly ordered vin and vout ports with one token each")

    graph, input_rows, requirements = _fixed_context(archive_path)
    if transition["metadata"] != requirements:
        raise ValueError("transition requirements differ from the fixed verifier and owner requirements")
    declared = {place["name"]: place for place in actual["places"]}
    for arc, source in zip(incoming, input_rows, strict=True):
        metadata = {"carrier": "archived-outpoint", "actual_outpoint": source["id"],
                    "satoshis": source["satoshis"], "script_sha256": source["script_sha256"]}
        if "token" in source:
            metadata["token"] = source["token"]
        expected = {"name": arc["place"], "type": source["kind"], "initial": 1, "capacity": 1, "metadata": metadata}
        if declared[arc["place"]] != expected or arc["type"] != source["kind"]:
            raise ValueError(f"{arc['name']}: declared input differs from the fixed parent")
    for arc in outgoing:
        expected = {"name": arc["place"], "type": "token", "initial": 0, "capacity": 1,
                    "metadata": {"carrier": "proposed-utxo"}}
        if declared[arc["place"]] != expected or arc["type"] != "token":
            raise ValueError(f"{arc['name']}: unsupported output requirement")

    result = construct_fixture_spend(archive_path, logical_model(graph), payouts, signer)
    for arc, produced in zip(outgoing, result.cpn["places"][-2:], strict=True):
        declared[arc["place"]]["metadata"].update(produced["metadata"])
    transition["metadata"] = {**transition["metadata"], "actual_txid": result.transaction.txid(),
                              "status": "constructed; chain admission not established"}
    checked = validate_document(actual)
    if not checked["ok"]:
        raise ValueError(f"constructed logical CPN is invalid: {checked['diagnostics']}")
    return replace(result, cpn=checked["model"])

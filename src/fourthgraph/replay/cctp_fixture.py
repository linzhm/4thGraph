"""Construct and validate a public-key-only CCTP historical-parent test fixture."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize

from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata, chain_verdict
from fourthgraph.bsv.transaction import Transaction
from fourthgraph.workflow.cctp_archive import OWNER_OFFSET, QUANTITY_OFFSET, read_archive
from fourthgraph.workflow.cctp_declared_fixture import construct_declared_fixture_spend, fixture_declaration
from fourthgraph.workflow.logical_cpn import parse_net


def inspect_bundle(bundle):
    """Revalidate the raw transaction and parent scripts, using the pinned engine."""
    if bundle.get("schema_version") != 1 or bundle.get("scope") != "historical-parent-script-fixture":
        raise ValueError("expected a historical-parent fixture bundle")
    chain = chain_metadata()
    if chain["commit"] != CONTEXT_PIN or bundle["chain_gang"]["commit"] != CONTEXT_PIN:
        raise ValueError("fixture verification requires pinned chain-gang")
    recorded_node = bundle.get("node_verdicts")
    if recorded_node is not None and (len(recorded_node) != 3 or
                                      any(type(verdict) is not bool for verdict in recorded_node)):
        raise ValueError("invalid recorded BSV Node verdicts")
    tx = Transaction.parse(bytes.fromhex(bundle["transaction"]))
    parents = tuple(Transaction.parse(bytes.fromhex(raw)) for raw in bundle["parents"])
    if len(tx.inputs) != 3 or len(tx.outputs) != 2 or len(parents) != 3:
        raise ValueError("fixture requires three inputs and two outputs")
    if any(txin.txid != parent.txid_wire() or txin.vout >= len(parent.outputs)
           for txin, parent in zip(tx.inputs, parents, strict=True)):
        raise ValueError("transaction input does not match its parent")
    model = parse_net(bundle["cpn"]).describe()
    transition, = model["transitions"]
    places = {place["name"]: place for place in model["places"]}
    ports = [arc["place"] for arc in transition["inputs"]]
    if [places[point]["metadata"]["actual_outpoint"] for point in ports] != [
            f"{txin.txid[::-1].hex()}:{txin.vout}" for txin in tx.inputs]:
        raise ValueError("logical inputs do not match actual outpoints")
    if [places[arc["place"]]["metadata"]["actual_outpoint"] for arc in transition["outputs"]] != [
            f"{tx.txid()}:{i}" for i in range(2)]:
        raise ValueError("logical outputs do not match actual outpoints")

    def describe(point, output):
        place = places[point]
        metadata = place["metadata"]
        if (metadata["satoshis"] != output.value or metadata["script_sha256"] != sha256(output.script).hexdigest()):
            raise ValueError("logical Place differs from its locking output")
        data = {"outpoint": metadata["actual_outpoint"], "satoshis": output.value, "kind": place["type"]}
        if place["type"] == "token":
            token = metadata["token"]
            if (token["quantity"] != int.from_bytes(output.script[QUANTITY_OFFSET:QUANTITY_OFFSET + 8], "little")
                    or token["owner_compressed"] != output.script[OWNER_OFFSET:OWNER_OFFSET + 33].hex()):
                raise ValueError("logical token state differs from the locking output")
            data.update(quantity=token["quantity"], owner=token["owner_compressed"])
        return data

    inputs = [describe(point, parent.outputs[txin.vout])
              for point, parent, txin in zip(ports, parents, tx.inputs, strict=True)]
    outputs = [describe(arc["place"], output) for arc, output in zip(transition["outputs"], tx.outputs, strict=True)]
    if not chain_verdict(tx, parents):
        raise ValueError("chain-gang rejected the fixture transaction")
    return {"txid": tx.txid(), "bytes": len(tx.serialize()), "inputs": inputs, "outputs": outputs,
            "chain_gang": True, "node_verdicts": recorded_node,
            "verification_scope": "provided-parents-only"}


def build_fixture(archive_path):
    """Build the documented fixture using public test secrets and optional loopback node."""
    _, digest = read_archive(archive_path)
    graph = fixture_declaration(archive_path)
    key = SigningKey.from_secret_exponent(21, curve=SECP256k1)
    alice = key.verifying_key.to_string("compressed")
    bob = SigningKey.from_secret_exponent(22, curve=SECP256k1).verifying_key.to_string("compressed")

    def signer(vin, digest_to_sign, owner):
        if vin not in (1, 2) or owner != alice:
            raise ValueError("unexpected fixture signing request")
        for attempt in range(256):
            signature = key.sign_digest_deterministic(digest_to_sign, hashfunc=sha256,
                                                      sigencode=sigencode_der_canonize,
                                                      extra_entropy=bytes([attempt]))
            if len(signature) == 70:
                return signature
        raise ValueError("fixture cannot find a 70-byte signature")

    spend = construct_declared_fixture_spend(archive_path, graph, ((276, bob), (224, alice)), signer)
    chain = chain_metadata()
    if chain["commit"] != CONTEXT_PIN:
        raise ValueError("fixture verification requires pinned chain-gang")
    bundle = {"schema_version": 1, "scope": "historical-parent-script-fixture", "archive_sha256": digest,
              "transaction": spend.transaction.serialize().hex(),
              "parents": [tx.serialize().hex() for tx in spend.parents], "cpn": spend.cpn,
              "chain_gang": chain, "node_verdicts": None}
    if "REGTEST_URL" in os.environ:
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        verdicts = node.verdicts(spend.transaction, spend.parents, timeout_us=2_000_000)
        if verdicts != [True, True, True]:
            raise ValueError(f"BSV Node rejected fixture input: {verdicts}")
        bundle["node_verdicts"] = verdicts
        bundle["bsv_node_version"] = node.version
    inspect_bundle(bundle)
    return bundle


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("archive", type=Path)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    try:
        bundle = build_fixture(args.archive)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(bundle, indent=2) + "\n")
    except (ImportError, IndexError, KeyError, OSError, TypeError, ValueError) as error:
        cli.error(str(error))
    print(args.output)


if __name__ == "__main__":
    main()

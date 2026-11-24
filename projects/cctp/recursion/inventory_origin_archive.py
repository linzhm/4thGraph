"""Extract four actual old v3 token origins from an adopted capacity regtest.

The legacy aggregate certifies the four parent continuity digests. Each actual
TxOut is authenticated separately by the old full-node wallet relation. An
inventory-origin proof can then translate the externally approved four-leaf
list to a Merkle root; it does not perform the old wallet checks in-circuit.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from capacity_tree import capacity_plan
from capacity_verifier import CapacityVerifier
from certified_wallet_provenance import CertifiedWalletProvenance
from committed_verifier import load_artifact, load_verifying_key, standalone_witness, verifier_lock
from cross_chain_fixture import AdoptedBsvChain
from inventory_origin import origin_statement
from inventory_tree import InventoryLeaf, InventoryState, inventory_root
from mint import MintPolicy
from projects.cctp.evm.bsv_burn_evidence import BsvTransactionLocation
from run_recursive_mimo import Regtest
from shared.evaluate import evaluate
from shared.transaction import Input, Transaction
from statement import AssetDescriptor


def extract(directory, key_file, node, previous_summary):
    previous = json.loads(previous_summary.read_text())
    run = json.loads((directory / "summary.json").read_text())
    key_data = json.loads(key_file.read_text())
    key, relation = load_verifying_key(key_data)
    key_digest = bytes.fromhex(key_data["continuity_key_digest"])
    if key_digest.hex() != previous["continuity_key_digest"]:
        raise ValueError("unexpected old continuity key")
    ledger = run["transactions"]
    labels = {rec["txid"]: label for label, rec in ledger.items()}
    locations = {bytes.fromhex(rec["txid"])[::-1]: BsvTransactionLocation(
        bytes.fromhex(rec["blockhash"])[::-1], rec["height"]) for rec in ledger.values()}
    issuance = Input(bytes.fromhex(ledger["setup"]["txid"])[::-1], 0).outpoint()
    asset = AssetDescriptor(1, issuance, 6, 7, b"r" * 32, b"p" * 32)
    scope = asset.asset_id()
    if scope.hex() != previous["asset_id"]:
        raise ValueError("recorded issuance outpoint or asset policy is different")
    mint = MintPolicy(asset, 84532, b"r" * 20, node.minter_key, lambda _: b"")
    verifier = CapacityVerifier(mint, node.freeze_key, key, relation, key_digest,
                                certified_mints=True, certified_admin=True, shared_ordinary_guard=True,
                                capacity=64, compressed_ancestry=True)
    chain = AdoptedBsvChain(node.node, {txid: loc.block_hash[::-1].hex() for txid, loc in locations.items()})
    provenance = CertifiedWalletProvenance(verifier, chain.call, chain.confirmation_policy(asset), locations.get)
    payment = Transaction.parse(bytes.fromhex(node.node.call("getrawtransaction", previous["payment"]["txid"])))
    if payment.txid() != previous["payment"]["txid"]:
        raise ValueError("wrong adopting payment")
    records, leaves, parent_digests = [], [], []
    for vin, expected in enumerate(previous["token_parents"][:4], 2):
        selected = payment.inputs[vin]
        txid = selected.txid[::-1].hex()
        if (txid, selected.vout) != (expected["txid"], expected["vout"]):
            raise ValueError("archived source selection differs from the actual payment vin")
        label = labels[txid]
        checkpoint = json.loads((directory / f"{label}-checkpoint.json").read_text())
        parent = Transaction.parse(bytes.fromhex(checkpoint["transaction"]))
        certified = provenance.check_creation(parent, selected.vout)
        loc = certified.location
        if (parent.txid(), loc.height, loc.block_hash[::-1].hex()) != (
                txid, expected["height"], expected["blockhash"]):
            raise ValueError("wrong live source transaction or confirming block")
        if provenance.valid_creation(parent, len(parent.outputs)-1):
            raise ValueError("receipt was accepted as a token output")
        if node.node.call("gettxout", txid, selected.vout, False) is not None:
            raise ValueError("expected these historical sources to have been spent")
        state = certified.state
        record = InventoryState(state.quantity, parent.outputs[selected.vout].value, state.owner, state.frozen)
        leaf = InventoryLeaf(scope, selected.outpoint(), record)
        leaves.append(leaf)
        parent_digests.append(certified.proof_digest)
        records.append(dict(expected, payment_vin=vin, asset_id=scope.hex(), owner=state.owner.hex(),
                            quantity=state.quantity, sats=record.sats, frozen=state.frozen,
                            outpoint_wire=selected.outpoint().hex(), source_leaf=leaf.digest().hex(),
                            continuity_digest=certified.proof_digest.hex(), verifier_hash=certified.verifier_hash.hex(),
                            verifier_outpoint=certified.verifier_outpoint.hex(),
                            current_unspent=False, receipt_vout_rejected=True))
    # At capacity eight the second level has two root children; duplicate-pad
    # the fourth source and take the first child, which covers exactly 0..3.
    four_digest = capacity_plan(scope, key_digest, 8, parent_digests).receipt.parents[0]
    nodes = [proof for proof in run["aggregate_proofs"].values() if proof["proof_digest"] == four_digest.hex()]
    if len(nodes) != 1:
        raise ValueError("could not identify the unique archived four-parent aggregate")
    path = directory / nodes[0]["artifact"]
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != nodes[0]["proof_sha256"]:
        raise ValueError("archived aggregate proof file differs")
    ak, ar, signals, proof = load_artifact(json.loads(raw))
    expected_signals = tuple(int.from_bytes(four_digest[i:i+16], "big") for i in (0, 16))
    if (ak, ar, signals) != (key, relation, expected_signals):
        raise ValueError("old four-parent proof key or public limbs differ")
    witness = standalone_witness(key, relation, signals, proof)
    if evaluate(witness + verifier_lock(key, relation)) != ([b"\x01"], []):
        raise ValueError("old four-parent aggregate failed the Script evaluator")
    statement = origin_statement([leaf.digest() for leaf in leaves])
    if inventory_root(leaves) != statement.root:
        raise ValueError("source and payment root conventions disagree")
    return {"scope": "External old v3 full-node creation checks for four already-spent B2G outputs; inventory key certifies a permutation of their approved leaves.",
            "node": node.evidence["node"], "payment_txid": payment.txid(), "issuance_outpoint_wire": issuance.hex(),
            "historical_continuity_key": key_digest.hex(), "source_approval_anchor": statement.anchor.hex(),
            "inventory_root": statement.root.hex(), "origin_statement": statement.encode().hex(),
            "old_four_parent_aggregate": {"digest": four_digest.hex(), "artifact": path.name,
                                          "sha256": sha256(raw).hexdigest(), "script_evaluator_verified": True},
            "origins": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--old-key", type=Path, required=True)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    previous = Path(__file__).resolve().parents[1] / "fixtures/v3-capacity-64-distinct-regtest-summary.json"
    report = extract(args.archive, args.old_key, Regtest(args.node_url, args.cookie), previous)
    with args.out.open("x") as f:
        json.dump(report, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()

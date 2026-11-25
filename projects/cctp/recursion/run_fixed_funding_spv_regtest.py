"""Re-prove a fixed-funding control spend using an index-free receipt."""

import argparse
import json
import lzma
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from time import perf_counter

from covenant_backtrace import ISSUANCE_AMOUNTS, MINT_BYTES, PAYMENT_BYTES, Policy, token_output
from payment_cost import measure_bundle
from regtest_mint import Node
from run_covenant_backtrace_regtest import ParentProver, _payment, _signed, save
from run_freeze_probe_regtest import read_key
from run_inventory_wide_regtest import test_signer
from run_recursive_mimo import Regtest
from run_secure_receipt_replay import adopt_through
from shared.transaction import Transaction
from snarkjs_adapter import load_artifacts
from spv_payment import RegtestHeaderChain, verify_receipt
from spv_regtest import confirmed_packet, header_chain, packet_bytes, payment_packets, read_packet


def receive(chain, evidence, policy, funding_id, txid, owner, units, vout=0):
    def authenticate(tx, parents):
        source = tx.inputs[0]
        if len(tx.inputs) == 1 and len(tx.serialize()) == MINT_BYTES:
            return (source.txid == policy.root_txid and vout == 0
                    and 0 <= source.vout < len(ISSUANCE_AMOUNTS) and ISSUANCE_AMOUNTS[source.vout] == units)
        return (len(tx.inputs) == 3 and len(tx.serialize()) == PAYMENT_BYTES and source.txid == funding_id
                and source.vout in (0, 1) and parents[funding_id].outputs[source.vout].script == policy.lock)

    payment, parents = evidence
    started = perf_counter()
    receipt = verify_receipt(chain, payment, parents, txid_wire=bytes.fromhex(txid)[::-1], vout=vout,
                             expected_output=token_output(funding_id, units, owner), authenticate=authenticate,
                             activation_height=2)
    return receipt.transaction, {"outpoint_wire": receipt.outpoint.hex(), "quantity": units, "owner": owner.hex(),
                                 "confirmations": receipt.confirmations, "fee_sats": receipt.fee,
                                 "spend_status": receipt.spend_status.value, "verify_seconds": perf_counter() - started,
                                 "packet_bytes": packet_bytes(payment, parents)}


def reject(reason, *args):
    try:
        receive(*args)
    except ValueError as error:
        if reason not in str(error):
            raise
        return str(error)
    raise AssertionError("wallet accepted mismatched evidence")


def replay(archive, report, pins, proofs):
    chain = RegtestHeaderChain(tuple(bytes.fromhex(item) for item in archive["headers"]))
    funding_id = bytes.fromhex(pins["verifier_funding"])[::-1]
    payments, funding = [], None
    for height_label, proof_label, owner_id, units, artifact_path in zip(
            ("first_block", "second_block"), ("first_proof_archived", "second_proof_live"),
            (22, 23), (275, 350), proofs, strict=True):
        raw = artifact_path.read_bytes()
        artifact = json.loads(raw)
        if (sha256(raw).hexdigest() != report[proof_label]["proof_artifact_sha256"]
                or artifact["verifying_key_sha256"] != pins["verifying_key_sha256"]
                or artifact["parent_checkpoint_profile"] != "parent-provenance-2x2"
                or artifact["test_only"] is not True):
            raise ValueError("proof differs from the pinned evaluation artifact")
        key, _, proof = load_artifacts(artifact, artifact, artifact["public_signals"])
        policy = Policy(bytes.fromhex(pins["issuance_root"])[::-1], key, prove_provenance=True)
        if sha256(policy.lock).hexdigest() != pins["verifier_lock_sha256"]:
            raise ValueError("the proof key does not generate the pinned lock")
        location = report[height_label]
        txid = location["txid"]
        evidence = archive["receipts"][txid]
        packet = read_packet(chain, evidence["payment"])
        prevouts = tuple(read_packet(chain, entry) for entry in evidence["parents"])
        owner, _ = test_signer(owner_id)
        tx, _ = receive(chain, (packet, prevouts), policy, funding_id, txid, owner, units)
        if (packet.inclusion.height != location["height"]
                or packet.inclusion.block_hash()[::-1].hex() != location["blockhash"]):
            raise ValueError("archived receipt differs from the independent node record")
        actual = {parent.txid_wire(): parent for parent, _ in (item.open(chain) for item in prevouts)}
        funding = actual[funding_id]
        slots = tuple((actual[item.txid], item.vout) for item in tx.inputs[1:])
        if len({item.txid for item in tx.inputs[1:]}) != 2:
            raise ValueError("expected two distinct token parents")
        if tx.inputs[0].script != policy.verifier_witness(tx, funding, slots, proof):
            raise ValueError("archived Groth16 artifact does not generate the executed witness")
        if any(item.raw in txin.script for item in prevouts for txin in tx.inputs):
            raise ValueError("full direct parent serialization entered the payment witness")
        payments.append(tx)
    first, second = payments
    if second.inputs[1].txid != first.txid_wire() or second.inputs[1].vout != 0:
        raise ValueError("second payment does not spend Bob's independently verified outpoint")
    observed = measure_bundle(payment=payments, verifier_funding=(funding,), preparation=(), settlement=())
    if observed != report["payment_and_funding"] or len(first.serialize()) != len(second.serialize()):
        raise ValueError("archived transaction sizes differ from the pinned result")
    return {"verified_payments": [f"{tx.txid()}:0" for tx in payments],
            "each_payment_bytes": len(first.serialize()), "bundle_bytes": observed["total"]["bytes"],
            "full_direct_parent_bytes_in_witness": 0, "historical_delta_bytes": 0,
            "open_replenishment": False}


def run(source, clone, summary, pins, params, prover, out):
    if (source.call("getblockchaininfo")["chain"] != "regtest"
            or clone.node.call("getblockchaininfo")["chain"] != "regtest"
            or clone.node.call("getblockcount") != 0 or clone.node.call("getconnectioncount") != 0):
        raise ValueError("use a fresh isolated regtest clone")
    records = summary["transactions"]
    manifest = json.loads((params / "manifest.json").read_text())
    key, _ = read_key(json.loads((params / "key.json").read_text()), "plain")
    policy = Policy(bytes.fromhex(pins["issuance_root"])[::-1], key, prove_provenance=True)
    funding_id = bytes.fromhex(pins["verifier_funding"])[::-1]
    if (manifest["profile"] != "parent-provenance-2x2" or manifest["test_only"] is not True
            or manifest["verifying_key_sha256"] != pins["verifying_key_sha256"]
            or sha256(policy.lock).hexdigest() != pins["verifier_lock_sha256"]):
        raise ValueError("parameters differ from receiver pins")
    adopt_through(source, clone.node, records["alice-to-bob"]["height"])
    bob, sign_bob = test_signer(22)
    carol, _ = test_signer(23)
    alice, _ = test_signer(21)
    chain = header_chain(clone.node)
    first_id, prior_id, copy_id = (records[label]["txid"] for label in ("alice-to-bob", "bob-mint", "copied-token"))
    first_data, prior_data, copy_data = (payment_packets(clone.node, txid) for txid in (first_id, prior_id, copy_id))

    # Receive, build, and prove entirely from the exported evidence and Bob's signer.
    first, bob_info = receive(chain, first_data, policy, funding_id, first_id, bob, 275)
    prior, prior_info = receive(chain, prior_data, policy, funding_id, prior_id, bob, 150)
    inclusion, direct_parents = first_data
    missing_parent = inclusion, direct_parents[:-1]
    bad_header = replace(inclusion.inclusion, header=bytes(80))
    wrong_block = replace(inclusion, inclusion=bad_header), direct_parents
    negatives = {
        "copied_token": reject("unauthorized", chain, copy_data, policy, funding_id, copy_id, alice, 300),
        "wrong_vout": reject("outpoint", chain, first_data, policy, funding_id, first_id, bob, 275, 1),
        "wrong_amount": reject("amount", chain, first_data, policy, funding_id, first_id, bob, 276),
        "missing_parent": reject("missing actual parent", chain, missing_parent, policy, funding_id, first_id, bob, 275),
        "wrong_block": reject("Merkle inclusion", chain, wrong_block, policy, funding_id, first_id, bob, 275),
    }
    funding = next(tx for tx, _ in (packet.open(chain) for packet in direct_parents) if tx.txid_wire() == funding_id)
    bob_parents = ((first, 0), (prior, 0))
    with ParentProver(prover, params, manifest, out) as session:
        proof, proof_record = session.prove("independent-bob-to-carol", funding, bob_parents, policy)
    draft = _payment(funding, 1, bob_parents, ((350, carol), (75, bob)))
    second = _signed(draft, policy, funding, bob_parents, proof, sign_bob)
    if second.txid() == records["bob-to-carol"]["txid"] or len({i.txid for i in second.inputs[1:]}) != 2:
        raise AssertionError("expected a freshly proved spend of two distinct parents")
    clone.include("bob-to-carol", second, (funding, first, prior))
    carol_chain = chain.adopt(header_chain(clone.node))
    second_data = payment_packets(clone.node, second.txid())
    _, carol_info = receive(carol_chain, second_data, policy, funding_id, second.txid(), carol, 350)

    for (_, parents), spend in ((first_data, first), (second_data, second)):
        if any(parent.raw in item.script for parent in parents for item in spend.inputs):
            raise AssertionError("full direct parent serialization found in payment witness")
    issuance_labels = ("setup", "issuance-root", "alice-mint-1", "alice-mint-2", "bob-mint")
    issuance = tuple(Transaction.parse(confirmed_packet(clone.node, records[label]["txid"]).raw)
                     for label in issuance_labels)
    cost = measure_bundle(payment=(first, second), verifier_funding=(funding,), preparation=(), settlement=())
    report = {"scope": "fixed preconfirmed verifier funding control", "open_replenishment": False,
              "node": clone.evidence["node"], "test_only_verifying_key_sha256": pins["verifying_key_sha256"],
              "first_block": records["alice-to-bob"], "second_block": clone.evidence["transactions"]["bob-to-carol"],
              "first_proof_archived": summary["payments"]["alice-to-bob"], "second_proof_live": proof_record,
              "prover_startup_seconds": session.startup_seconds, "node_timings": clone.confirmation_timings,
              "bob": bob_info, "bob_prior": prior_info, "carol": carol_info, "negative_cases": negatives,
              "payment_delta_bytes": len(second.serialize()) - len(first.serialize()), "embedded_parent_bytes": 0,
              "payment_and_funding": cost, "issuance": measure_bundle(issuance=issuance)}
    save(out / "report.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-url", "clone-url"):
        parser.add_argument("--" + name)
    for name in ("source-cookie", "clone-cookie", "params", "prover", "out"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--recipient-policy", required=True, type=Path)
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--proofs", type=Path, nargs=2, metavar=("ALICE", "BOB"))
    args = parser.parse_args()
    summary = json.loads(args.summary.read_text())
    pins = json.loads(args.recipient_policy.read_text())
    if args.replay:
        if not args.proofs:
            parser.error("--replay requires both --proofs")
        with lzma.open(args.replay, "rt") as stream:
            result = replay(json.load(stream), summary, pins, args.proofs)
        print(json.dumps(result, indent=2))
        return
    if not all((args.source_url, args.clone_url, args.source_cookie, args.clone_cookie,
                args.params, args.prover, args.out)):
        parser.error("live replay requires the source and clone node settings, --params, --prover, and --out")
    args.out.mkdir()
    run(Node(args.source_url, args.source_cookie), Regtest(args.clone_url, args.clone_cookie), summary, pins,
        args.params, args.prover, args.out)


if __name__ == "__main__":
    main()

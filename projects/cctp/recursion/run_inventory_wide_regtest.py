"""Two full 64-to-64 payments under a bounded issuer-approved inventory policy."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from time import perf_counter

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize

import inventory_payment as payment
from inventory_tree import InventoryLeaf, InventoryState, inventory_root, multi_path
from inventory_wide import wide_verifier_lock, wide_witness
from regtest_mint import sign_p2pkh
from run_recursive_mimo import Regtest
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all


def test_signer(secret):
    """Public test keys only. Fixed DER length isolates history-dependent bytes."""
    key = SigningKey.from_secret_exponent(secret, curve=SECP256k1)

    def sign(digest):
        for nonce_attempt in range(256):
            der = key.sign_digest_deterministic(digest, hashfunc=sha256, sigencode=sigencode_der_canonize,
                                                extra_entropy=bytes([nonce_attempt]))
            if len(der) == 70:
                return der
        raise ValueError("could not obtain fixed-width test signature")

    return key.verifying_key.to_string("compressed"), sign


def run(node, *, compact_holder=False, compact_outputs=False):
    if node.node.call("getblockchaininfo")["chain"] != "regtest" or node.node.call("getconnectioncount"):
        raise ValueError("an isolated BSV regtest is required")
    issuer, issuer_sign = test_signer(13)
    wallets = dict(test_signer(i) for i in range(1000, 1128))
    owners = tuple(wallets)
    coinbase = node.node.fund(node.address)
    issue_lock = push(issuer) + asm("OP_CHECKSIG")
    setup_outputs = (Output(2_000, issue_lock),) * 128 + (Output(50_000, issue_lock),) * 2 + (
        Output(2_000_000, asm("OP_1")),) * 2
    if coinbase.outputs[0].value <= sum(output.value for output in setup_outputs):
        raise ValueError("insufficient isolated test subsidy")
    setup = node.include("issuance-anchor", sign_p2pkh(
        Transaction((Input(coinbase.txid_wire(), 0),), setup_outputs), coinbase, 0,
        SigningKey.from_secret_exponent(11, curve=SECP256k1)), (coinbase,))
    scope = hash256(b"BSV/CCTP/wide-inventory/regtest/v1\0" + Input(setup.txid_wire(), 0).outpoint())
    coupons = tuple(Input(setup.txid_wire(), i).outpoint() for i in (128, 129))
    parts = payment.token_parts(scope, coupons, input_count=66, compact_holder=compact_holder)

    def from_setup(index, output):
        tx = Transaction((Input(setup.txid_wire(), index),), (output,))
        previous = setup.outputs[index]
        if previous.script == issue_lock:
            digest = hash256(preimage_all(tx, 0, previous.value, previous.script))
            tx = tx.with_script(0, push(issuer_sign(digest) + b"\x41"))
        return tx

    # Submit all independent origins before mining a single block.
    parents, leaves = [], []
    for i, owner in enumerate(owners):
        state = InventoryState(200 + i, 1000, owner)
        parent = from_setup(i, payment.token_output(state, parts))
        validate_at_heights(parent, (setup,), spend_height=200, activation_height=2, utxo_heights=(3,))
        node.node.submit(parent)
        parents.append(parent)
        leaves.append(InventoryLeaf(scope, Input(parent.txid_wire(), 0).outpoint(), state))
    blockhash = node.node.call("generatetoaddress", 1, node.address)[0]
    block = node.node.call("getblock", blockhash, 1)
    if not {parent.txid() for parent in parents}.issubset(block["tx"]):
        raise AssertionError("missing distinct inventory origins")
    for i, parent in enumerate(parents):
        node.evidence["transactions"][f"origin-{i:03}"] = dict(
            txid=parent.txid(), blockhash=blockhash, height=block["height"], bytes=len(parent.serialize()))

    positions = tuple(range(0, 128, 2))
    records = []
    for generation in range(2):
        label = f"payment-{generation + 1}"
        root = inventory_root(leaves)
        started = perf_counter()
        lock = wide_verifier_lock(scope, parts, root, compact_outputs=compact_outputs)
        verifier = node.include(label + "-verifier", from_setup(130 + generation, Output(1_500_000, lock)), (setup,))
        companion = node.include(label + "-companion", from_setup(128 + generation,
            Output(10_000, payment.companion_lock(verifier, input_count=66))), (setup,))
        funded = perf_counter()
        selected = [leaves[i] for i in positions]
        previous = tuple(parents[i] for i in positions)
        selected_inputs = tuple(Input(leaf.outpoint[:32], int.from_bytes(leaf.outpoint[32:], "little"))
                                for leaf in selected)
        out_states = tuple(replace(leaf.state, owner=owners[(i + 1 + generation) % len(owners)],
                                   quantity=leaf.state.quantity + (1 if i % 2 else -1))
                           for i, leaf in enumerate(selected))
        tx = Transaction((Input(verifier.txid_wire(), 0), Input(companion.txid_wire(), 0), *selected_inputs),
                         tuple(payment.token_output(state, parts) for state in out_states))

        def signed(candidate, outputs):
            final = candidate.with_script(0, wide_witness(candidate, scope, leaves, positions, outputs,
                                                         compact_outputs=compact_outputs,
                                                         verifier_sats=verifier.outputs[0].value))
            final = final.with_script(1, payment.companion_witness(candidate, companion))
            for j, (leaf, parent) in enumerate(zip(selected, previous, strict=True)):
                vin = j + 2
                witness = payment.token_witness(candidate, vin, parent.outputs[candidate.inputs[vin].vout],
                                                companion, wallets[leaf.state.owner], compact_holder=compact_holder)
                final = final.with_script(vin, witness)
            return final

        final = signed(tx, out_states)
        signed_at = perf_counter()
        negatives = {}
        if generation == 0:
            inflated = (replace(out_states[0], quantity=out_states[0].quantity + 1), *out_states[1:])
            changed = replace(tx, outputs=tuple(payment.token_output(state, parts) for state in inflated))
            negatives["changed_total_with_fresh_signatures"] = node.reject(signed(changed, inflated))
            if compact_outputs:
                # Keep the disclosed state and actual satoshis, alter only the locking suffix.
                changed_script = replace(tx.outputs[0], script=tx.outputs[0].script + asm("OP_NOP"))
                changed = replace(tx, outputs=(changed_script, *tx.outputs[1:]))
                negatives["changed_output_lock_with_fresh_signatures"] = node.reject(signed(changed, out_states))
        node.include(label, final, (verifier, companion, *previous))
        witnesses = [len(item.script) for item in final.inputs]
        body = final.serialize()
        parent_raws = {parent.txid(): parent.serialize() for parent in previous}
        records.append({
            "root": root.hex(), "scope": scope.hex(), "txid": final.txid(), "token_inputs": 64, "token_outputs": 64,
            "distinct_token_parents": len(parent_raws), "payer_signed_seconds": signed_at - funded,
            "verifier_and_companion_setup_seconds": funded - started, "node_timings": node.confirmation_timings[label],
            "payment_bytes": len(body), "verifier_funding_bytes": len(verifier.serialize()),
            "companion_funding_bytes": len(companion.serialize()), "verifier_lock_bytes": len(lock),
            "companion_lock_bytes": len(companion.outputs[0].script),
            "total_including_dedicated_funding": len(body) + len(verifier.serialize()) + len(companion.serialize()),
            "verifier_witness_bytes": witnesses[0], "companion_witness_bytes": witnesses[1],
            "holder_witnesses_bytes": sum(witnesses[2:]), "holder_witness_each_bytes": sorted(set(witnesses[2:])),
            "companion_raw_copies_in_holders": sum(i.script.count(companion.serialize()) for i in final.inputs[2:]),
            "prevout_vector_bytes_per_holder": 36 * len(tx.inputs), "sibling_hash_bytes": len(multi_path(leaves, positions)) * 32,
            "successor_lock_bytes_per_output": len(final.outputs[0].script),
            "full_token_parent_raw_occurrences": sum(i.script.count(raw) for i in final.inputs for raw in parent_raws.values()),
            "actual_input_outpoints": [txi.outpoint().hex() for txi in final.inputs[2:]], "negatives": negatives,
        })
        for i, pos in enumerate(positions):
            leaves[pos] = InventoryLeaf(scope, Input(final.txid_wire(), i).outpoint(), out_states[i])
            parents[pos] = final
    if records[0]["distinct_token_parents"] != 64 or records[1]["distinct_token_parents"] != 1:
        raise AssertionError("unexpected direct-parent topology")
    if records[0]["payment_bytes"] != records[1]["payment_bytes"] or any(r["full_token_parent_raw_occurrences"] for r in records):
        raise AssertionError("unexpected depth-dependent wire data under the fixed-DER test profile")
    return {
        "profile": "F" if compact_outputs else ("E-compact" if compact_holder else "E"),
        "trust": "Test issuer approves each inventory root through one of two real issuance coupons. "
                 "This does not supply a permissionless recursive root update.",
        "statistics": "Two disjoint fixed-width coupons, fixed 70-byte DER test signer, alternating 64 of 128. "
                      "Second payment spends all 64 authorized outputs of the first.",
        "scope": scope.hex(), "origin_transaction_bytes": sum(rec["bytes"] for name, rec in node.evidence["transactions"].items()
                                                                if name.startswith("origin-")),
        "payments": records, **node.evidence,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--compact-holder", action="store_true",
                        help="bind the holder preimage using the compact Script after OP_CODESEPARATOR")
    parser.add_argument("--compact-outputs", action="store_true",
                        help="encode only output states and authenticate exact reconstructed TxOuts with ForkID ALL")
    args = parser.parse_args()
    if args.compact_outputs and not args.compact_holder:
        parser.error("select --compact-holder as the comparison baseline for --compact-outputs")
    args.out.mkdir()
    result = run(Regtest(args.node_url, args.cookie), compact_holder=args.compact_holder,
                 compact_outputs=args.compact_outputs)
    (args.out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")

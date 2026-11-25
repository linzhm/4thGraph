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
import inventory_ticket as ticket
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


def run(node, *, compact_holder=False, compact_outputs=False, ticket_mode=None, recipient_respend=False):
    ticket_profiles = {"metadata": "G", "derive": "H", "template": "I"}
    if recipient_respend:
        if ticket_mode not in (None, "template"):
            raise ValueError("the recipient-respend comparison uses template tickets")
        ticket_mode = "template"
    if ticket_mode is not None and ticket_mode not in ticket_profiles:
        raise ValueError("unknown inventory ticket mode")
    if node.node.call("getblockchaininfo")["chain"] != "regtest" or node.node.call("getconnectioncount"):
        raise ValueError("an isolated BSV regtest is required")
    issuer, issuer_sign = test_signer(13)
    if ticket_mode:
        compact_holder = compact_outputs = True
    ticket_key, ticket_sign = test_signer(2020)
    wallets = dict(test_signer(i) for i in range(1000, 1128))
    owners = tuple(wallets)
    received_vout = 31
    origin_owners = owners
    if recipient_respend:
        origin_owners = (owners[-1], owners[received_vout]) * 64
    coinbase = node.node.fund(node.address)
    issue_lock = push(issuer) + asm("OP_CHECKSIG")
    setup_outputs = (Output(2_000, issue_lock),) * 128 + (Output(50_000, issue_lock),) * 2 + (
        Output(2_000_000, asm("OP_1")),) * 2
    if ticket_mode:
        setup_outputs += (Output(2_000_000, asm("OP_1")),) * 2
    if coinbase.outputs[0].value <= sum(output.value for output in setup_outputs):
        raise ValueError("insufficient isolated test subsidy")
    setup = node.include("issuance-anchor", sign_p2pkh(
        Transaction((Input(coinbase.txid_wire(), 0),), setup_outputs), coinbase, 0,
        SigningKey.from_secret_exponent(11, curve=SECP256k1)), (coinbase,))
    scope = hash256(b"BSV/CCTP/wide-inventory/regtest/v1\0" + Input(setup.txid_wire(), 0).outpoint())
    coupons = tuple(Input(setup.txid_wire(), i).outpoint() for i in (128, 129))
    if ticket_mode == "template":
        parts = ticket.template_ticket_token_parts(scope, coupons, input_count=66)
    elif ticket_mode == "derive":
        parts = ticket.ticket_token_parts(scope, coupons, input_count=66, derive_prevouts=True)
    elif ticket_mode:
        parts = ticket.ticket_token_parts(scope, coupons, input_count=66)
    else:
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
    for i, owner in enumerate(origin_owners):
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
        if recipient_respend and generation == 1:
            # Spend one received output and 63 existing coins. Selecting one
            # leaf of each pair keeps the membership proof width identical.
            positions = tuple(2 * i if i == received_vout else 2 * i + 1 for i in range(64))
        label = f"payment-{generation + 1}"
        root = inventory_root(leaves)
        started = perf_counter()
        lock = wide_verifier_lock(scope, parts, root, compact_outputs=compact_outputs)
        verifier = node.include(label + "-verifier", from_setup(130 + generation, Output(1_500_000, lock)), (setup,))
        companion_lock = (ticket.ticket_lock(verifier, ticket_key) if ticket_mode
                          else payment.companion_lock(verifier, input_count=66))
        companion = node.include(label + "-companion", from_setup(128 + generation, Output(10_000, companion_lock)), (setup,))
        funded = perf_counter()
        selected = [leaves[i] for i in positions]
        previous = tuple(parents[i] for i in positions)
        selected_inputs = tuple(Input(leaf.outpoint[:32], int.from_bytes(leaf.outpoint[32:], "little"))
                                for leaf in selected)
        recipients = (owners[generation * 64:(generation + 1) * 64] if recipient_respend
                      else owners[generation + 1:generation + 65])
        out_states = tuple(replace(leaf.state, owner=recipients[i],
                                   quantity=leaf.state.quantity + (1 if i % 2 else -1))
                           for i, leaf in enumerate(selected))
        tx = Transaction((Input(verifier.txid_wire(), 0), Input(companion.txid_wire(), 0), *selected_inputs),
                         tuple(payment.token_output(state, parts) for state in out_states))

        def signed(candidate, outputs, ticket_parent=companion, origin_material=None):
            disclosed_ticket = ticket_parent if origin_material is None else origin_material
            final = candidate.with_script(0, wide_witness(candidate, scope, leaves, positions, outputs,
                                                         compact_outputs=compact_outputs,
                                                         verifier_sats=verifier.outputs[0].value))
            companion_witness = (ticket.ticket_witness(candidate, ticket_parent, ticket_sign) if ticket_mode
                                 else payment.companion_witness(candidate, ticket_parent))
            final = final.with_script(1, companion_witness)
            for j, (leaf, parent) in enumerate(zip(selected, previous, strict=True)):
                vin = j + 2
                prior = parent.outputs[candidate.inputs[vin].vout]
                if ticket_mode == "template":
                    witness = ticket.template_ticket_token_witness(candidate, vin, prior, disclosed_ticket,
                                                                   wallets[leaf.state.owner], coupons)
                elif ticket_mode == "derive":
                    witness = ticket.ticket_token_witness(candidate, vin, prior, ticket_parent,
                                                          wallets[leaf.state.owner], derive_prevouts=True)
                else:
                    witness = payment.token_witness(candidate, vin, prior, ticket_parent,
                                                    wallets[leaf.state.owner], compact_holder=compact_holder)
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
            if ticket_mode:
                # Both lookalike funding outputs are real; all wallet and ticket signatures are refreshed.
                other = node.include("negative-same-verifier-lock", from_setup(132, verifier.outputs[0]), (setup,))
                altered = replace(tx, inputs=(Input(other.txid_wire(), 0), *tx.inputs[1:]))
                negatives["same_verifier_lock_other_txid"] = node.reject(signed(altered, out_states))
                copied = node.include("negative-same-ticket-lock", from_setup(133, companion.outputs[0]), (setup,))
                altered = replace(tx, inputs=(tx.inputs[0], Input(copied.txid_wire(), 0), *tx.inputs[2:]))
                negatives["ticket_from_unapproved_coupon"] = node.reject(signed(altered, out_states, copied, companion))
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
            "prevout_vector_bytes_per_holder": 36 * (len(tx.inputs) - (2 if ticket_mode in ("derive", "template") else 0)),
            "sibling_hash_bytes": len(multi_path(leaves, positions)) * 32,
            "successor_lock_bytes_per_output": len(final.outputs[0].script),
            "full_token_parent_raw_occurrences": sum(i.script.count(raw) for i in final.inputs for raw in parent_raws.values()),
            "actual_input_outpoints": [txi.outpoint().hex() for txi in final.inputs[2:]], "negatives": negatives,
        })
        for i, pos in enumerate(positions):
            leaves[pos] = InventoryLeaf(scope, Input(final.txid_wire(), i).outpoint(), out_states[i])
            parents[pos] = final
    if records[0]["distinct_token_parents"] != 64 or records[1]["distinct_token_parents"] != (64 if recipient_respend else 1):
        raise AssertionError("unexpected direct-parent topology")
    if records[0]["payment_bytes"] != records[1]["payment_bytes"] or any(r["full_token_parent_raw_occurrences"] for r in records):
        raise AssertionError("unexpected depth-dependent wire data under the fixed-DER test profile")
    if records[0]["total_including_dedicated_funding"] != records[1]["total_including_dedicated_funding"]:
        raise AssertionError("unexpected change in the size including verifier and companion funding")
    return {
        "profile": "I-distinct" if recipient_respend else ticket_profiles.get(
            ticket_mode, "F" if compact_outputs else ("E-compact" if compact_holder else "E")),
        **({"ticket_wallet_key": ticket_key.hex()} if ticket_mode else {}),
        "trust": "Test issuer approves each inventory root through one of two real issuance coupons. "
                 "This does not supply a permissionless recursive root update.",
        "statistics": ("Two one-wallet payments to 64 distinct external recipients, 64 different token parents each. "
                       "The second payer spends the received vout 31 and 63 existing single-origin UTXOs. "
                       "Fixed 70-byte DER test signatures." if recipient_respend else
                       "Two disjoint fixed-width coupons, fixed 70-byte DER test signer, alternating 64 of 128. "
                       "Second payment spends all 64 authorized outputs of the first."),
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
    parser.add_argument("--ticket-mode", choices=("metadata", "derive", "template"),
                        help="use compact holders/outputs and a wallet ticket naming the required verifier outpoint")
    parser.add_argument("--recipient-respend", action="store_true",
                        help="template tickets; spend one received output alongside 63 independent existing coins")
    args = parser.parse_args()
    if args.compact_outputs and not args.compact_holder and not (args.ticket_mode or args.recipient_respend):
        parser.error("select --compact-holder as the comparison baseline for --compact-outputs")
    args.out.mkdir()
    result = run(Regtest(args.node_url, args.cookie), compact_holder=args.compact_holder,
                 compact_outputs=args.compact_outputs, ticket_mode=args.ticket_mode, recipient_respend=args.recipient_respend)
    (args.out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")

"""Reconcile every serialized byte of the small and wide inventory payments."""

import argparse
import json
import lzma
from hashlib import sha256
from pathlib import Path

from chronicle_preimage import CHRONICLE_ALL
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der
from inventory_payment import TOKEN_TAG, companion_lock, proof_lock, token_parts
from inventory_ticket import template_ticket_token_parts, ticket_token_parts
from inventory_tree import (
    InventoryLeaf,
    InventoryState,
    inventory_root,
    membership_path,
    multi_path,
)
from inventory_wide import wide_verifier_lock
from run_freeze_probe_regtest import read_key
from transfer import COMPACT_SCRIPTCODE

from shared.script import asm, number, push
from shared.transaction import (
    Input,
    Output,
    Transaction,
    blob,
    compact,
    hash256,
    preimage_all,
    preimage_otda,
)


def require(check, explanation):
    if not check:
        raise ValueError(explanation)


def parent(txin, ledger):
    return ledger[txin.txid[::-1].hex()]


def partition(raw, entries):
    """An ordered byte partition must recreate the field byte for byte."""
    require(raw == b"".join(data for _, data in entries), "field/push order or content differs")
    result = {}
    for name, data in entries:
        result[name] = result.get(name, 0) + len(data)
    return result


def pushed(name, data):
    return [(name + "_push", push(data)[: len(push(data)) - len(data)]), (name, data)]


def signature(raw):
    length = raw[0]
    sig = raw[1 : 1 + length]
    require(
        0 < length <= 75
        and len(sig) == length
        and sig[-1:] == b"\x41"
        and sig[:1] == b"\x30"
        and sig[1] == length - 3,
        "expected ForkID ALL DER signature",
    )
    return [("signature_push", raw[:1]), ("signature_der", sig[:-1]), ("sighash_byte", sig[-1:])]


def forkid(pre, lock, *, compact_suffix=False):
    field = blob(lock)
    require(pre[104 : 104 + len(field)] == field, "previous scriptCode mismatch")
    return [
        ("preimage_push", pushed("preimage", pre)[0][1]),
        ("before_scriptCode", pre[:104]),
        ("scriptCode_length", compact(len(lock))),
        ("scriptCode_compact_suffix" if compact_suffix else "scriptCode_lock_copy", lock),
        ("after_scriptCode", pre[104 + len(field) :]),
    ]


def shell(tx):
    return {
        "version_locktime_counts": 8 + len(compact(len(tx.inputs))) + len(compact(len(tx.outputs))),
        "outpoints_sequences": 40 * len(tx.inputs),
        "input_script_lengths": sum(len(compact(len(i.script))) for i in tx.inputs),
        "output_satoshis_and_script_lengths": sum(8 + len(compact(len(o.script))) for o in tx.outputs),
    }


def token_fields(script, scope, state, parts):
    prefix, native = parts
    require(prefix == push(TOKEN_TAG + scope) + bytes([50]), "unsupported token header")
    return partition(
        script,
        [
            ("tag_and_scope_push", prefix[:-1]),
            ("state_push", prefix[-1:]),
            ("state", state),
            ("holder_and_verifier_guard", native),
        ],
    )


def verifier_fields(tx, summary, row, ledger, parts):
    cert = summary["certificates"][row["source_certificate"]]
    root = bytes.fromhex(cert["root"])
    scope = bytes.fromhex(summary["scope"])
    members = []
    for rec in cert["members"]:
        state = bytes.fromhex(rec["state"])
        token = InventoryState(
            int.from_bytes(state[:8], "little"),
            int.from_bytes(state[8:16], "little"),
            state[16:49],
            bool(state[-1]),
        )
        leaf = InventoryLeaf(scope, bytes.fromhex(rec["outpoint_wire"]), token)
        require(leaf.digest().hex() == rec["leaf"], "certificate leaf mismatch")
        members.append(leaf)
    script = tx.inputs[0].script
    source = script[: cert["witness_bytes"]]
    require(sha256(source).hexdigest() == cert["witness_sha256"], "source witness mismatch")
    if summary["profile"] == "D":
        require(source == push(b"".join(m.digest() for m in members)), "incorrect approved leaf hashes")
        entries = pushed("approved_list", b"".join(m.digest() for m in members))
    else:
        entries = [("source_proof_pushes", source)]
    payment = row.get("payment_proof")
    if payment:
        proof = script[len(source) : len(source) + payment["witness_bytes"]]
        require(sha256(proof).hexdigest() == payment["witness_sha256"], "payment proof mismatch")
        entries.append(("payment_proof_pushes", proof))
    entries += pushed("inventory_root", root)
    for i, pos in enumerate(row["selection"]):
        leaf = members[pos]
        inp = tx.inputs[2 + i]
        require(inp.outpoint() == leaf.outpoint, "selection differs from actual vin")
        prev = parent(inp, ledger).outputs[inp.vout]
        token_fields(prev.script, scope, leaf.state.encode(), parts)
        require(prev.value == leaf.state.sats, "wrong carrier value")
        if not payment:
            entries.append(("membership_indices", number(pos)))
            for sibling in membership_path(members, pos):
                entries += pushed("membership_sibling", sibling)
            entries += pushed("source_state", leaf.state.encode())
    for state in row["output_state_bytes"]:
        entries += pushed("successor_state", bytes.fromhex(state))
    return partition(script, entries + otda(tx))


def otda(tx):
    pre = preimage_otda(tx, 0, COMPACT_SCRIPTCODE, CHRONICLE_ALL)
    fields = [("otda_other", tx.version.to_bytes(4, "little") + compact(len(tx.inputs)))]
    for n, inp in enumerate(tx.inputs):
        fields += [
            ("otda_current_outpoints", inp.outpoint()),
            ("otda_other", blob(COMPACT_SCRIPTCODE if n == 0 else b"") + inp.sequence.to_bytes(4, "little")),
        ]
    fields.append(("otda_other", compact(len(tx.outputs))))
    for out in tx.outputs:
        fields += [
            ("otda_output_amount_and_length", out.value.to_bytes(8, "little") + compact(len(out.script))),
            ("otda_current_output_lock_copies", out.script),
        ]
    fields.append(("otda_other", tx.locktime.to_bytes(4, "little") + CHRONICLE_ALL.to_bytes(4, "little")))
    partition(pre, fields)
    return [pushed("otda", pre)[0]] + fields


def funding(tx, role, groth_locks=()):
    require(len(tx.inputs) == len(tx.outputs) == 1, "expected single-input, single-output funding")
    lock = tx.outputs[0].script
    result = shell(tx)
    sig = tx.inputs[0].script
    if sig:
        result.update(partition(sig, signature(sig)))
    for name, code in groth_locks:
        require(lock.count(code) == 1, "missing or duplicate embedded Groth16 verifier")
        result[name + "_groth16_lock"] = len(code)
    result[role + "_native_lock"] = len(lock) - sum(len(code) for _, code in groth_locks)
    require(sum(result.values()) == len(tx.serialize()), "funding does not reconcile")
    return result


def check_history(tx, ledger):
    frontier = {i.txid[::-1].hex() for i in tx.inputs[2:]}
    history = set()
    while frontier:
        known = (frontier & ledger.keys()) - history
        history.update(known)
        frontier = {i.txid[::-1].hex() for key in known for i in ledger[key].inputs} - history
    count = 0
    for key in history:
        raw = ledger[key].serialize()
        count += sum(inp.script.count(raw) for inp in tx.inputs) * len(raw)
    return {
        "known_token_creation_and_ancestor_txs": len(history),
        "literal_token_history_bytes_in_scriptSigs": count,
    }


def template_ticket_fields(ticket, coupons):
    """Partition the pieces the holder carries and reconstruct the exact signed funding bytes."""
    source = ticket.inputs[0]
    spent = ticket.outputs[0]
    der = dict(signature(source.script))["signature_der"]
    slot = coupons.index(source.outpoint())
    coupon = coupons[slot]
    verifier = spent.script[1:37]
    key = spent.script[39:-1]
    rebuilt = Transaction(
        (Input(coupon[:32], int.from_bytes(coupon[32:], "little"), push(der + b"\x41")),),
        (Output(spent.value, push(verifier) + asm("OP_DROP") + push(key) + asm("OP_CHECKSIG")),),
        version=2,
        locktime=0,
    )
    require(rebuilt.serialize() == ticket.serialize(), "template fields cannot reproduce the signed ticket")
    return (
        pushed("ticket_wallet_pubkey", key)
        + pushed("ticket_verifier_outpoint", verifier)
        + [("ticket_satoshis_number", number(spent.value))]
        + pushed("ticket_issuer_der", der)
        + [("ticket_coupon_slot_number", number(slot))]
    )


def support_scripts(tx, ledger, compact_holder=False, ticket_mode=None, coupons=()):
    parents = [parent(inp, ledger) for inp in tx.inputs]
    prevouts = b"".join(i.outpoint() for i in tx.inputs)
    scripts = {}
    if ticket_mode == "I":
        companion_evidence = template_ticket_fields(parents[1], coupons)
    else:
        companion_evidence = pushed("companion_funding_raw", parents[1].serialize())
    if ticket_mode in ("H", "I"):
        ticket = parents[1]
        verifier = ticket.outputs[0].script[1:37]
        ticket_outpoint = Input(hash256(ticket.serialize()), 0).outpoint()
        tail = b"".join(i.outpoint() for i in tx.inputs[2:])
        require(
            verifier + ticket_outpoint + tail == prevouts,
            "ticket and token outpoints differ from actual input order",
        )
        outpoints = pushed("token_prevouts", tail)
    else:
        outpoints = pushed("ordered_prevouts", prevouts)
    for n, inp in enumerate(tx.inputs[1:], 1):
        prev = parents[n].outputs[inp.vout]
        if ticket_mode and n == 1:
            scripts["companion"] = partition(inp.script, signature(inp.script))
            continue
        entries = []
        if n >= 2:
            entries += signature(inp.script)
            entries += companion_evidence
        entries += outpoints
        has_suffix = compact_holder and n >= 2
        script_code = COMPACT_SCRIPTCODE if has_suffix else prev.script
        entries += forkid(
            preimage_all(tx, n, prev.value, script_code), script_code, compact_suffix=has_suffix
        )
        scripts["companion" if n == 1 else f"holder{n - 2}"] = partition(inp.script, entries)
    return scripts


def verify_forkid_signature(tx, vin, spent, key, raw):
    partition(raw, signature(raw))
    signer = VerifyingKey.from_string(key, curve=SECP256k1, valid_encodings={"compressed"})
    digest = hash256(preimage_all(tx, vin, spent.value, spent.script))
    require(signer.verify_digest(raw[1:-1], digest, sigdecode=sigdecode_der), "invalid ForkID ALL signature")


def check_signed_ticket(tx, ticket, setup, coupons):
    """Read the two authority links from wire bytes independently of the wallet template."""
    require(len(ticket.inputs) == len(ticket.outputs) == 1, "expected one funding input and one output")
    issuer_input = ticket.inputs[0]
    require(issuer_input.outpoint() in coupons and issuer_input.txid == setup.txid_wire(), "wrong coupon")
    source = setup.outputs[issuer_input.vout]
    issuer_key = source.script[1:-1]
    require(
        len(issuer_key) == 33 and source.script == push(issuer_key) + asm("OP_CHECKSIG"),
        "wrong issuer lock",
    )
    verify_forkid_signature(ticket, 0, source, issuer_key, issuer_input.script)
    require(tx.inputs[1].outpoint() == Input(ticket.txid_wire(), 0).outpoint(), "wrong spent ticket")
    spent = ticket.outputs[0]
    key = spent.script[39:-1]
    expected_lock = push(tx.inputs[0].outpoint()) + asm("OP_DROP") + push(key) + asm("OP_CHECKSIG")
    require(
        len(key) == 33 and spent.script == expected_lock,
        "ticket does not authorize the actual verifier outpoint or the signing key",
    )
    verify_forkid_signature(tx, 1, spent, key, tx.inputs[1].script)
    return {
        "issuer_coupon_wire": issuer_input.outpoint().hex(),
        "signed_verifier_outpoint_wire": tx.inputs[0].outpoint().hex(),
        "ticket_outpoint_wire": tx.inputs[1].outpoint().hex(),
        "ticket_pubkey": key.hex(),
    }


def audit_row(tx, ledger, summary, row, parts, groth_locks):
    require(len(tx.inputs) == 4 and len(tx.outputs) == 2, "expected 2+2 inputs and two outputs")
    parents = [parent(inp, ledger) for inp in tx.inputs]
    scripts = {"verifier": verifier_fields(tx, summary, row, ledger, parts), **support_scripts(tx, ledger)}
    scope = bytes.fromhex(summary["scope"])
    outputs = [
        token_fields(out.script, scope, bytes.fromhex(state), parts)
        for out, state in zip(tx.outputs, row["output_state_bytes"], strict=True)
    ]
    wire = shell(tx)
    wire.update({k + "_scriptSig": sum(v.values()) for k, v in scripts.items()})
    wire["token_output_locks"] = sum(sum(v.values()) for v in outputs)
    require(
        sum(wire.values()) == len(tx.serialize()) == row["raw_bytes"], "payment wire bytes do not reconcile"
    )
    require(
        parents[1].outputs[0].script == companion_lock(parents[0]), "companion does not pin actual verifier"
    )
    vf = funding(parents[0], "verifier", groth_locks)
    cf = funding(parents[1], "companion")
    total = sum(wire.values()) + sum(vf.values()) + sum(cf.values())
    require(total == row["total_including_both_tickets"], "payment and funding do not reconcile")
    return {
        "txid": tx.txid(),
        "total_with_dedicated_funding": total,
        "payment": wire,
        "scriptSigs": scripts,
        "actual_token_locks": outputs,
        "verifier_funding": vf,
        "companion_funding": cf,
        "history": check_history(tx, ledger),
    }


def compare(first, onward):
    def changes(left, right):
        keys = dict.fromkeys((*left, *right))
        return {k: right.get(k, 0) - left.get(k, 0) for k in keys if left.get(k, 0) != right.get(k, 0)}

    return {
        "payment": changes(first["payment"], onward["payment"]),
        "scriptSigs": {k: changes(v, onward["scriptSigs"][k]) for k, v in first["scriptSigs"].items()},
        "verifier_funding": changes(first["verifier_funding"], onward["verifier_funding"]),
        "companion_funding": changes(first["companion_funding"], onward["companion_funding"]),
        "total_with_dedicated_funding": onward["total_with_dedicated_funding"]
        - first["total_with_dedicated_funding"],
    }


def sum_fields(items):
    combined = {}
    for fields in items:
        for name, size in fields.items():
            combined[name] = size + combined.get(name, 0)
    return combined


def wide_leaf(scope, tx, index, parts):
    prev = tx.outputs[index]
    offset = len(parts[0])
    state = prev.script[offset : offset + 50]
    token_fields(prev.script, scope, state, parts)
    token = InventoryState(
        int.from_bytes(state[:8], "little"),
        int.from_bytes(state[8:16], "little"),
        state[16:49],
        bool(state[-1]),
    )
    require(prev.value == token.sats and token.encode() == state, "unparsable wide token")
    return InventoryLeaf(scope, Input(tx.txid_wire(), index).outpoint(), token)


def compact_output_context(tx, funding, scope, parts):
    states = b"".join(wide_leaf(scope, tx, i, parts).state.encode() for i in range(len(tx.outputs)))
    prevouts = b"".join(inp.outpoint() for inp in tx.inputs)
    preimage = preimage_all(tx, 0, funding.outputs[tx.inputs[0].vout].value, COMPACT_SCRIPTCODE)
    require(preimage[4:36] == hash256(prevouts), "compact W input commitment differs from actual vin")
    require(
        preimage[-40:-8] == hash256(b"".join(out.serialize() for out in tx.outputs)),
        "compact W output commitment differs from actual TxOuts",
    )
    return (
        pushed("packed_successor_states", states)
        + pushed("ordered_prevouts", prevouts)
        + forkid(preimage, COMPACT_SCRIPTCODE, compact_suffix=True)
    )


def audit_distinct_payer(tx, preceding, origin_points, ledger, scope, parts):
    """Verify one sender, independent receipts, and the exact repeated disclosure from wire."""
    inputs = tx.inputs[2:]
    points = {inp.outpoint() for inp in inputs}
    parent_count = len({inp.txid for inp in inputs})
    require(parent_count == len(inputs) == 64, "expected 64 distinct token parent txids")
    remaining = origin_points
    previous_vouts = []
    if preceding is not None:
        preceding_txid = preceding.txid_wire()
        previous_vouts = [inp.vout for inp in inputs if inp.txid == preceding_txid]
        require(previous_vouts == [31], "expected only output 31 of the first payment")
        remaining = origin_points - {inp.outpoint() for inp in preceding.inputs[2:]}
    fresh_origins = points & remaining
    require(len(fresh_origins) + len(previous_vouts) == 64, "unexpected or already spent origin")

    vector = b"".join(inp.outpoint() for inp in inputs)
    encoded_vector = push(vector)
    owners = set()
    for vin, inp in enumerate(inputs, 2):
        source = parent(inp, ledger)
        owner = wide_leaf(scope, source, inp.vout, parts).state.owner
        sig_push = inp.script[:1 + inp.script[0]]
        verify_forkid_signature(tx, vin, source.outputs[inp.vout], owner, sig_push)
        owners.add(owner)
        require(inp.script.count(encoded_vector) == 1, "holder lacks an exact copy of the ordered token outpoints")
    require(len(owners) == 1, "token inputs belong to multiple sending keys")
    payer = owners.pop()
    recipients = {wide_leaf(scope, tx, vout, parts).state.owner for vout in range(len(tx.outputs))}
    require(len(recipients) == 64 and payer not in recipients, "expected 64 external recipient keys")
    return {
        "payer_pubkey": payer.hex(),
        "distinct_recipient_keys": len(recipients),
        "self_payment_outputs": 0,
        "verified_holder_signatures": len(inputs),
        "distinct_token_parent_txids": parent_count,
        "inputs_from_unspent_initial_origins": len(fresh_origins),
        "vouts_from_preceding_payment": previous_vouts,
        "token_outpoint_vector_sha256": sha256(vector).hexdigest(),
        "token_outpoint_vector_bytes": len(vector),
        "holder_witness_copies": len(inputs),
        "vector_payload_in_holders_bytes": len(inputs) * len(vector),
        "vector_payload_after_first_holder_copy_bytes": (len(inputs) - 1) * len(vector),
    }


def audit_wide(ledger, summary):
    scope = bytes.fromhex(summary["scope"])
    labels = summary["transactions"]
    setup = ledger[labels["issuance-anchor"]["txid"]]
    coupons = tuple(Input(setup.txid_wire(), i).outpoint() for i in (128, 129))
    profile = summary["profile"]
    ticket_mode = {"G": "G", "H": "H", "I": "I", "I-distinct": "I"}.get(profile)
    compact_outputs = profile == "F" or bool(ticket_mode)
    compact_holder = compact_outputs or profile == "E-compact"
    if ticket_mode == "I":
        parts = template_ticket_token_parts(scope, coupons, input_count=66)
    elif ticket_mode:
        parts = ticket_token_parts(scope, coupons, input_count=66, derive_prevouts=profile == "H")
    else:
        parts = token_parts(scope, coupons, input_count=66, compact_holder=compact_holder)
    origins = tuple(ledger[labels[f"origin-{n:03}"]["txid"]] for n in range(128))
    leaves = [wide_leaf(scope, origin, 0, parts) for origin in origins]
    rows = {}
    for n, row in enumerate(summary["payments"], 1):
        tx = ledger[row["txid"]]
        require(len(tx.inputs) == 66 and len(tx.outputs) == 64, "unexpected wide shape")
        vf, cf = (parent(inp, ledger) for inp in tx.inputs[:2])
        if ticket_mode:
            ticket_binding = check_signed_ticket(tx, cf, setup, coupons)
            require(ticket_binding["ticket_pubkey"] == summary["ticket_wallet_key"], "recorded ticket signer differs")
        else:
            require(cf.outputs[0].script == companion_lock(vf, input_count=66), "incorrect wide companion")
        positions_by_point = {leaf.outpoint: i for i, leaf in enumerate(leaves)}
        positions = [positions_by_point[inp.outpoint()] for inp in tx.inputs[2:]]
        root = inventory_root(leaves)
        require(
            root.hex() == row["root"]
            and vf.outputs[0].script
            == wide_verifier_lock(scope, parts, root, compact_outputs=compact_outputs),
            "wide verifier failed to pin approved root",
        )
        siblings = multi_path(leaves, positions)
        entries = []
        for value in reversed(siblings):
            entries += pushed("membership_sibling", value)
        records = [
            (name, part)
            for pos in positions
            for name, part in (
                ("membership_indices", bytes([pos])),
                ("source_state", leaves[pos].state.encode()),
            )
        ]
        encoded = b"".join(v for _, v in records)
        entries += [pushed("packed_records", encoded)[0]] + records
        entries += compact_output_context(tx, vf, scope, parts) if compact_outputs else otda(tx)
        vf_script = partition(tx.inputs[0].script, entries)
        support = support_scripts(tx, ledger, compact_holder, ticket_mode, coupons)
        companion = support.pop("companion")
        holder = sum_fields(support.values())
        holders = list(support.values())
        require(all(rec == holders[0] for rec in holders), "expected uniform fixed-DER holder input fields")
        output_fields = []
        for idx, pos in enumerate(positions):
            leaf = wide_leaf(scope, tx, idx, parts)
            leaves[pos] = leaf
            output_fields.append(token_fields(tx.outputs[idx].script, scope, leaf.state.encode(), parts))
        outputs = sum_fields(output_fields)
        scripts = {"verifier": vf_script, "companion": companion, "holders_64": holder}
        wire = {
            **shell(tx),
            **{k + "_scriptSig": sum(v.values()) for k, v in scripts.items()},
            "token_output_locks": sum(outputs.values()),
        }
        verifier = funding(vf, "verifier")
        companion_funds = funding(cf, "companion")
        total = sum(wire.values()) + sum(verifier.values()) + sum(companion_funds.values())
        require(
            sum(wire.values()) == len(tx.serialize()) == row["payment_bytes"]
            and total == row["total_including_dedicated_funding"],
            "wide wire total mismatch",
        )
        rows[f"payment-{n}"] = {
            "txid": tx.txid(),
            "total_with_dedicated_funding": total,
            "payment": wire,
            "scriptSigs": scripts,
            "representative_holder": holders[0],
            "actual_token_locks_64": outputs,
            "verifier_funding": verifier,
            "companion_funding": companion_funds,
            "history": check_history(tx, ledger),
        }
        if ticket_mode:
            rows[f"payment-{n}"]["ticket_binding"] = ticket_binding
    first = ledger[rows["payment-1"]["txid"]]
    second = ledger[rows["payment-2"]["txid"]]
    if profile == "I-distinct":
        require(
            all(len(tx.inputs) == len(tx.outputs) == 1 and tx.inputs[0].outpoint() == Input(setup.txid_wire(), i).outpoint()
                for i, tx in enumerate(origins)),
            "unexpected initial token funding",
        )
        origin_points = {Input(origin.txid_wire(), 0).outpoint() for origin in origins}
        alice = audit_distinct_payer(first, None, origin_points, ledger, scope, parts)
        bob = audit_distinct_payer(second, first, origin_points, ledger, scope, parts)
        require(alice["payer_pubkey"] != bob["payer_pubkey"], "second payment must have a different sending key")
        rows["payment-1"]["source_topology"] = alice
        rows["payment-2"]["source_topology"] = bob
    else:
        first_txid = first.txid_wire()
        require(
            all(inp.txid == first_txid and inp.vout == i for i, inp in enumerate(second.inputs[2:])),
            "wide payment did not consume all 64 preceding outputs in order",
        )
    # The initial holder locks are paid once at issuance. Successor locks are already counted in payment.
    preparation = {
        "issuance_anchor_bytes": len(setup.serialize()),
        "initial_128_origin_transactions_bytes": sum(len(origin.serialize()) for origin in origins),
        "initial_128_token_lock_bytes_within_origins": sum(len(origin.outputs[0].script) for origin in origins),
    }
    require(
        preparation["initial_128_origin_transactions_bytes"] == summary["origin_transaction_bytes"],
        "incorrect recorded origin transaction bytes",
    )
    experiment_bytes = (
        preparation["issuance_anchor_bytes"]
        + preparation["initial_128_origin_transactions_bytes"]
        + sum(row["total_with_dedicated_funding"] for row in rows.values())
    )
    protocol_records = [info for name, info in labels.items() if not name.startswith("negative-")]
    require(
        len(protocol_records) == 135
        and experiment_bytes == sum(len(ledger[info["txid"]].serialize()) for info in protocol_records),
        "setup, origins, payment funding and two payments must account for the entire positive path",
    )
    return {
        "scope": summary["scope"],
        "one_time_preparation": preparation,
        "two_payments_with_funding_and_issuance_bytes": experiment_bytes,
        "rows": rows,
        "previous_to_next": compare(rows["payment-1"], rows["payment-2"]),
    }


def audit(directory, profile):
    prefix = "inventory-" + ("e-wide" if profile == "E" else profile.lower()) + "-regtest"
    summary = json.loads((directory / (prefix + "-summary.json")).read_text())
    with lzma.open(directory / (prefix + ".json.xz"), "rt") as stream:
        archive = json.load(stream)
    require(
        summary["profile"] == archive["profile"] == profile and summary["scope"] == archive["scope"],
        "archive and summary differ",
    )
    ledger = {
        k: Transaction.parse(bytes.fromhex(raw))
        for k, raw in {**archive["funding"], **archive["transactions"]}.items()
    }
    require(all(tx.txid() == k for k, tx in ledger.items()), "txid differs from serialized transaction")
    if profile in ("E", "E-compact", "F", "G", "H", "I", "I-distinct"):
        return audit_wide(ledger, summary)
    labels = summary["transactions"]
    setup = ledger[labels["issuance-anchor-and-coupons"]["txid"]]
    coupons = tuple(Input(setup.txid_wire(), i).outpoint() for i in range(4, 7))
    parts = token_parts(bytes.fromhex(summary["scope"]), coupons)
    locks = []
    for role, name in (("source", "initial-proof.json"), ("payment", "first-selection-proof.json")):
        if name in archive["proof_artifacts"]:
            key, _ = read_key(json.loads(archive["proof_artifacts"][name]), "plain")
            locks.append((role, proof_lock(key)))
    rows = {}
    for label, row in zip(
        ("first-selection", "second-selection", "recipient-respend"), summary["payments"], strict=True
    ):
        require(row["txid"] == labels[label]["txid"], "wrong payment label")
        rows[label] = audit_row(ledger[row["txid"]], ledger, summary, row, parts, locks)
    first_id = rows["first-selection"]["txid"]
    require(
        ledger[rows["recipient-respend"]["txid"]].inputs[2].txid[::-1].hex() == first_id,
        "respend does not consume first selection",
    )
    return {
        "scope": summary["scope"],
        "rows": rows,
        "previous_to_next": compare(rows["first-selection"], rows["recipient-respend"]),
    }


PROFILES = ("B", "C", "D", "E", "E-compact", "F", "G", "H", "I", "I-distinct")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=PROFILES)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = {p: audit(args.directory, p) for p in args.profiles}
    for profile, baseline in (("F", "E-compact"), ("G", "F"), ("H", "G"), ("I", "H")):
        if profile in report and baseline in report:
            name = "bytes_minus_" + baseline.replace("-", "_") + "_first_payment"
            report[profile][name] = compare(report[baseline]["rows"]["payment-1"], report[profile]["rows"]["payment-1"])
            report[profile]["issuance_and_two_payments_bytes_minus_" + baseline.replace("-", "_")] = (
                report[profile]["two_payments_with_funding_and_issuance_bytes"]
                - report[baseline]["two_payments_with_funding_and_issuance_bytes"]
            )
    args.out.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

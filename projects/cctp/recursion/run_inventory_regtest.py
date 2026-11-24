"""Measure two independently selected inventory payments followed by an immediate respend."""
import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from time import perf_counter

from ecdsa import SECP256k1, SigningKey

import inventory_payment as payment
from chronicle_context_script import bind_all_context
from inventory_origin import direct_origin_script, origin_statement
from inventory_tree import InventoryLeaf, InventoryState, inventory_root, membership_path
from public_inputs import verification_key_point
from regtest_mint import sign_p2pkh
from run_freeze_probe_regtest import read_key
from run_recursive_mimo import Regtest
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from snarkjs_adapter import load_artifacts
from test_operational_token import fixture_signer
from verifier import unlocking_fields, unlocking_script


def write(path, record):
    path.write_text(json.dumps(record, indent=2) + "\n")


@contextmanager
def resident_prover(binary, params, profile):
    manifest = json.loads((params / "manifest.json").read_text())
    command = [str(binary), "-mode", "session", "-profile", profile, "-dir", str(params)]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    def reply():
        line = process.stdout.readline()
        if not line:
            raise RuntimeError(f"{profile} prover closed its session (exit status {process.poll()})")
        return json.loads(line)
    try:
        ready = reply()
        if (ready.get("ready") is not True or ready.get("profile") != profile
                or ready.get("verifying_key_sha256") != manifest["verifying_key_sha256"]):
            raise ValueError("resident prover loaded the wrong parameters")

        def request(statement, private, path):
            payload = {"id": path.name, "statement": statement.hex(), "openings": private.hex(),
                       "out": str(path.resolve())}
            process.stdin.write(json.dumps(payload) + "\n")
            process.stdin.flush()
            result = reply()
            if result.get("id") != path.name or result.get("ok") is not True:
                raise ValueError(f"{profile} proof failed: {result}")

        yield request
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()


def prove(binary, params, statement, private, path, key, resident=None):
    start = perf_counter()
    if resident is None:
        subprocess.run([str(binary), "-mode", "prove", "-dir", str(params), "-statement", statement.hex(),
                        "-openings", private.hex(), "-out", str(path)], check=True)
    else:
        resident(statement, private, path)
    process = perf_counter() - start
    data = json.loads(path.read_text())
    vk, signals, proof = load_artifacts(data, data, data["public_signals"])
    digest = hash256(statement)
    expected = tuple(int.from_bytes(digest[i:i+16], "big") for i in (0, 16))
    if tuple(signals) != expected or vk != key:
        raise ValueError("unexpected proof key or public statement")
    point = verification_key_point(vk.ic, signals) or (0, 0)
    raw = unlocking_script((*point, *unlocking_fields(vk, signals, proof, projective_g1=True, projective_g2=True)))
    return raw, {"native_prove_seconds": data["prove_seconds"], "native_verify_seconds": data["native_verify_seconds"],
                 "process_seconds": process, "process_mode": "resident" if resident else "one-shot", "encoded_seconds": perf_counter() - start - process,
                 "artifact_sha256": sha256(path.read_bytes()).hexdigest(), "witness_sha256": sha256(raw).hexdigest(),
                 "witness_bytes": len(raw), "digest": digest.hex(), "public_inputs": list(map(str, signals))}


def read_params(path, profile):
    manifest = json.loads((path / "manifest.json").read_text())
    if not manifest["test_only"] or manifest["profile"] != profile or manifest["commitments"] != 0:
        raise ValueError("expected matching plain test-only parameters")
    return read_key(json.loads((path / "key.json").read_text()), "plain")[0], manifest


def run(node, args):
    sessions, startup = {}, {}
    with ExitStack() as stack:
        if args.warm_provers:
            for role in ("origin", "payment"):
                binary = getattr(args, role + "_prover")
                if binary is None:
                    continue
                params = getattr(args, role + "_params")
                started = perf_counter()
                sessions[role] = stack.enter_context(resident_prover(binary, params, "inventory-" + role))
                startup[role] = perf_counter() - started
        result = _run(node, args, sessions)
        result["resident_startup_seconds"] = startup
        return result


def _run(node, args, sessions):
    if node.node.call("getblockchaininfo")["chain"] != "regtest" or node.node.call("getconnectioncount") != 0:
        raise ValueError("a disconnected regtest is required")
    directory = args.out
    private_mode = args.payment_params is not None
    direct = args.direct_origin
    # The twelve public test keys are confined to this disposable harness.
    holders = {fixture_signer(i)[0]: fixture_signer(i)[1] for i in range(15, 23)}
    owners = tuple(holders)
    issuer_key, issuer_sign = fixture_signer(13)
    issuer_lock = push(issuer_key) + asm("OP_CHECKSIG")
    coinbase = node.node.fund(node.address)
    per_output = min(2_000_000, coinbase.outputs[0].value // 12)
    if per_output < 100_000:
        raise ValueError("insufficient fixture subsidy")
    setup_candidate = Transaction((Input(coinbase.txid_wire(), 0),), tuple(
        Output(per_output, issuer_lock if i < 7 or i == 10 else asm("OP_1")) for i in range(11)
    ))
    setup = node.include("issuance-anchor-and-coupons", sign_p2pkh(
        setup_candidate, coinbase, 0, SigningKey.from_secret_exponent(11, curve=SECP256k1)), (coinbase,))
    coupons = tuple(Input(setup.txid_wire(), i).outpoint() for i in range(4, 7))
    scope = hash256(b"BSV/CCTP/inventory/authorized-lab-anchor/v1\x00" + Input(setup.txid_wire(), 0).outpoint())
    parts = payment.token_parts(scope, coupons)

    def issue(label, pos, outputs):
        current = Transaction((Input(setup.txid_wire(), pos),), outputs)
        if pos < 7 or pos == 10:
            prev = setup.outputs[pos]
            sig = issuer_sign(hash256(preimage_all(current, 0, prev.value, prev.script))) + b"\x41"
            current = current.with_script(0, push(sig))
        return node.include(label, current, (setup,))

    def inventory_record(entries):
        return [{"txid": parent.txid(), "vout": vout, "outpoint_wire": leaf.outpoint.hex(),
                 "state": leaf.state.encode().hex(), "leaf": leaf.digest().hex()}
                for parent, vout, leaf in entries]

    entries = []
    for i, quantity in enumerate((101, 203, 307, 409)):
        state = InventoryState(quantity, 1000, owners[i])
        parent = issue(f"test-issuer-origin-{i}", i, (payment.token_output(state, parts),))
        entries.append((parent, 0, InventoryLeaf(scope, Input(parent.txid_wire(), 0).outpoint(), state)))
    recipient_state = InventoryState(97, 1000, owners[4])
    recipient_origin = issue("recipient-existing-coin", 10, (payment.token_output(recipient_state, parts),))
    recipient_coin = (recipient_origin, 0, InventoryLeaf(scope, Input(recipient_origin.txid_wire(), 0).outpoint(),
                                                        recipient_state))
    write(directory / "origins.json", {"scope": scope.hex(), "initial": inventory_record(entries)})
    origin_key, origin_manifest = (None, None) if direct else read_params(args.origin_params, "inventory-origin")
    key_c, c_manifest = read_params(args.payment_params, "inventory-payment") if private_mode else (None, None)
    certs = {}
    first_payment_proof = None
    def certify(label, members):
        leaves = [entry[2] for entry in members]
        digests = tuple(leaf.digest() for leaf in leaves)
        source = origin_statement(digests)
        anchor = source.anchor
        root = inventory_root(leaves)
        if root != source.root:
            raise ValueError("source certificate and output inventory disagree")
        if direct:
            signature = push(b"".join(digests))
            details = {"source": "four approved leaf hashes in canonical issuance order",
                       "witness_bytes": len(signature), "witness_sha256": sha256(signature).hexdigest()}
        else:
            signature, details = prove(args.origin_prover, args.origin_params, source.encode(), source.opening,
                                       directory / f"{label}-proof.json", origin_key, sessions.get("origin"))
        certs[label] = {**details, "anchor": anchor.hex(), "root": root.hex(), "members": inventory_record(members)}
        return root, anchor, signature

    def spend(step, members, selected, cert, outputs, cert_label):
        nonlocal first_payment_proof
        label = ("first-selection", "second-selection", "recipient-respend")[step]
        root, anchor, origin_wit = cert
        started = perf_counter()
        if direct:
            lock = (payment.payment_rules(scope, parts, private_membership=False)
                    + direct_origin_script(anchor) + bind_all_context())
        else:
            lock = payment.verifier_lock(scope, parts, anchor, origin_key, payment_key=key_c)
        lock_prepared = perf_counter()
        verifier = issue(label + "-verifier", 7 + step, (Output(per_output // 2, lock),))
        companion = issue(label + "-companion", 4 + step,
                          (Output(5000, payment.companion_lock(verifier)),))
        funded = perf_counter()
        selected_entries = [members[i] for i in selected]
        previous = tuple(parent for parent, _, _ in selected_entries)
        parents = (verifier, companion, *previous)
        tx = Transaction(tuple(Input(p.txid_wire(), v) for p, v in (
            (verifier, 0), (companion, 0), *((p, v) for p, v, _ in selected_entries))),
            tuple(payment.token_output(state, parts) for state in outputs))
        leaves = [i[2] for i in members]
        openings = [(i, membership_path(leaves, i), leaves[i].state) for i in selected]
        payment_wit = None
        payment_record = None
        if private_mode:
            statement = (b"\x02" + scope + root + b"".join(txin.outpoint() for txin in tx.inputs[2:])
                         + b"".join(state.encode() for state in outputs))
            private = b"".join(state.encode() + bytes([idx]) + b"".join(siblings)
                               for idx, siblings, state in openings)
            payment_wit, payment_record = prove(args.payment_prover, args.payment_params, statement, private,
                                                directory / (label + "-proof.json"), key_c, sessions.get("payment"))

        def sign(candidate, outputs, openings, *, origin=origin_wit, selected_root=root, signer_override=None,
                 proof_witness=payment_wit):
            witness = payment.verifier_witness(candidate, selected_root, origin, outputs,
                openings=() if private_mode else openings, payment_witness=proof_witness)
            signed = candidate.with_script(0, witness).with_script(1, payment.companion_witness(candidate, companion))
            for vin, (parent, vout, leaf) in enumerate(selected_entries, 2):
                signer = signer_override if signer_override is not None and vin == 2 else holders[leaf.state.owner]
                signed = signed.with_script(vin, payment.token_witness(candidate, vin, parent.outputs[vout], companion, signer))
            return signed

        final = sign(tx, outputs, openings)
        ready = perf_counter()
        negatives = {}
        if not step:
            bad_states = (replace(outputs[0], quantity=outputs[0].quantity+1), outputs[1])
            changed = replace(tx, outputs=tuple(payment.token_output(i, parts) for i in bad_states))
            cases = {"inflation_with_new_holder_signatures": sign(changed, bad_states, openings),
                     "wrong_holder": sign(tx, outputs, openings, signer_override=holders[owners[7]]),
                     "wrong_root": sign(tx, outputs, openings, selected_root=bytes(32))}
            if not private_mode:
                cases["swap_membership_paths"] = sign(tx, outputs, openings[::-1])
            for name, candidate in cases.items():
                negatives[name] = node.reject(candidate)
        if private_mode and step == 0:
            first_payment_proof = payment_wit
            redirected = (replace(outputs[0], owner=owners[7]), outputs[1])
            changed = replace(tx, outputs=tuple(payment.token_output(s, parts) for s in redirected))
            negatives["new_recipient_with_stale_proof_and_new_signatures"] = node.reject(
                sign(changed, redirected, openings))
        if private_mode and step == 1:
            if first_payment_proof is None:
                raise ValueError("missing prior selection proof")
            negatives["other_selection_proof_same_origin_root"] = node.reject(
                sign(tx, outputs, openings, proof_witness=first_payment_proof))
        node.include(label, final, parents)
        for inp in final.inputs:
            if node.node.call("gettxout", inp.txid[::-1].hex(), inp.vout, False) is not None:
                raise AssertionError("confirmed payment left an input unspent")
        elapsed = node.confirmation_timings[label]
        record = {"txid": final.txid(), "selection": list(selected), "source_certificate": cert_label,
                  "verification_keys": int(not direct) + int(private_mode),
                  "new_payment_proofs": 1 if private_mode else 0, "payment_proof": payment_record,
                  "payment_prepare_to_signed_seconds": ready-funded,
                  "lock_generation_seconds": lock_prepared - started,
                  "ticket_prepare_and_confirm_seconds": funded - lock_prepared,
                  "raw_bytes": len(final.serialize()), "verifier_funding_bytes": len(verifier.serialize()),
                  "companion_funding_bytes": len(companion.serialize()),
                  "total_including_both_tickets": sum(len(t.serialize()) for t in (final,verifier,companion)),
                  "witness_sizes": [len(i.script) for i in final.inputs],
                  "origin_witness_matches_cached": final.inputs[0].script.startswith(origin_wit),
                  "token_parent_raw_occurrences": sum(i.script.count(p.serialize())
                      for i in final.inputs for p in {p.txid():p for p in previous}.values()),
                  "actual_input_outpoints": [i.outpoint().hex() for i in final.inputs],
                  "output_state_bytes": [s.encode().hex() for s in outputs],
                  "negatives": negatives, "node_timings": elapsed}
        return [(final, i, InventoryLeaf(scope, Input(final.txid_wire(),i).outpoint(), s)) for i,s in enumerate(outputs)], record

    initial_cert = certify("initial", entries)
    out_a = (InventoryState(300,1100,owners[4]),InventoryState(108,900,owners[0]))
    out_b = (InventoryState(400,1100,owners[5]),InventoryState(212,900,owners[1]))
    first, a = spend(0, entries, (0,2), initial_cert, out_a, "initial")
    # Build the recipient's next inventory as soon as its received transaction is confirmed.
    refresh_started = perf_counter()
    remaining = [first[0], recipient_coin, first[1], entries[1]]
    next_cert = certify("recipient", remaining)
    refresh_seconds = perf_counter() - refresh_started
    # The recipient alone spends the new payment and its own existing coin.
    # The original sender keeps the change, and the other two origins remain available.
    _, onward = spend(2, remaining, (0,1), next_cert,
                      (InventoryState(205,1000,owners[6]),InventoryState(192,1100,owners[4])), "recipient")
    _, b = spend(1, entries, (1,3), initial_cert, out_b, "initial")
    profile = "D" if direct else ("C" if private_mode else "B")
    return {"profile": profile, "scope": scope.hex(),
            "trust": "Test issuer approves origins and verifier companion tickets, including the new recipient list. "
                     "D opens that list directly; B and C check a proof of its permutation into a Merkle root.",
            "parameters": {"origin": origin_manifest, "payment": c_manifest}, "certificates": certs,
            "recipient_certificate_process_and_encoding_seconds": refresh_seconds,
            "payments": [a,b,onward], **node.evidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--direct-origin", action="store_true", help="D: open the approved four-leaf list in Script")
    parser.add_argument("--origin-prover", type=Path)
    parser.add_argument("--origin-params", type=Path)
    parser.add_argument("--payment-prover", type=Path)
    parser.add_argument("--payment-params", type=Path)
    parser.add_argument("--warm-provers", action="store_true",
                        help="load each test key once before starting the node lifecycle")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.payment_params) != bool(args.payment_prover):
        parser.error("payment prover and parameters must be supplied together")
    if args.direct_origin:
        if args.origin_prover or args.origin_params or args.payment_params or args.warm_provers:
            parser.error("the direct-origin profile takes no prover or parameters")
    elif not (args.origin_params and args.origin_prover):
        parser.error("provide both origin parameters and prover or use --direct-origin")
    args.out.mkdir()
    write(args.out / "summary.json", run(Regtest(args.node_url, args.cookie), args))


if __name__ == "__main__":
    main()

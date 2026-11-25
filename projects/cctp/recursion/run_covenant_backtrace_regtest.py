"""Run two actual distinct-parent payments with proof openings and Script rules."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import lzma
from pathlib import Path
import subprocess
from time import perf_counter

from covenant_backtrace import (ISSUANCE_AMOUNTS, MINT_BYTES, PAYMENT_BYTES, PROOF_BYTES, PROOF_FIELDS,
                                Policy, holder_witness, parent_layout, token_output, token_state)
from run_freeze_probe_regtest import read_key
from run_inventory_wide_regtest import test_signer
from run_recursive_mimo import Regtest
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from snarkjs_adapter import load_artifacts
from wallet_receipt import BlockInclusion


def save(path, data):
    with path.open("x") as stream:
        print(json.dumps(data, indent=2), file=stream)


class ParentProver:
    def __init__(self, binary, params, manifest, out):
        self.command = (str(binary.resolve()), "-mode", "session", "-profile", "parent-openings-2x2",
                        "-dir", str(params.resolve()))
        self.manifest = manifest
        self.out = out

    def __enter__(self):
        started = perf_counter()
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            ready = json.loads(self.process.stdout.readline())
            if ready.get("verifying_key_sha256") != self.manifest["verifying_key_sha256"]:
                raise ValueError("native session uses different proof parameters")
            self.startup_seconds = perf_counter() - started
            return self
        except BaseException:
            self.__exit__()
            raise

    def __exit__(self, *_):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()

    def prove(self, label, funding, parents, policy):
        statement = policy.statement(funding.txid_wire(), parents)
        native = bytearray()
        stark = bytearray(funding.txid_wire())
        for parent, vout in parents:
            raw = parent.serialize()
            layout = bytes([parent_layout(raw)])
            native.extend(layout + raw)
            stark.extend(layout + vout.to_bytes(4, "little") + raw)
        path = (self.out / f"{label}-proof.json").resolve()
        (self.out / f"{label}-stark-input.bin").write_bytes(stark)
        request = dict(id=label, statement=statement.hex(), parent=native.hex(), out=str(path))
        started = perf_counter()
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        reply = json.loads(self.process.stdout.readline())
        elapsed = perf_counter() - started
        if reply.get("id") != label or not reply.get("ok"):
            raise ValueError(f"native opening failed: {reply}")
        data = json.loads(path.read_text())
        key, _, proof = load_artifacts(data, data, data["public_signals"])
        if (key != policy.key or data["statement"] != statement.hex()
                or bytes.fromhex(data["statement_digest"]) != hash256(statement)):
            raise ValueError("proof statement or key differs")
        result = {
            "wall_seconds": elapsed, "prove_seconds": data["prove_seconds"],
            "native_verify_seconds": data["native_verify_seconds"], "statement_digest": data["statement_digest"],
            "proof_artifact_sha256": sha256(path.read_bytes()).hexdigest(),
        }
        print(f"{label} proved in {elapsed:.2f}s", flush=True)
        return proof, result


def confirmed(rpc, txid):
    record = rpc.call("getrawtransaction", txid, True)
    tx = Transaction.parse(bytes.fromhex(record["hex"]))
    block = rpc.call("getblock", record["blockhash"], 1)
    header = bytes.fromhex(rpc.call("getblockheader", block["hash"], False))
    txids = [bytes.fromhex(item)[::-1] for item in block["tx"]]
    proof = BlockInclusion.from_block(header, block["height"], txids, txids.index(tx.txid_wire()))
    if (tx.txid() != txid or proof.block_hash()[::-1].hex() != block["hash"]
            or rpc.call("getblockhash", block["height"]) != block["hash"] or block["confirmations"] < 1):
        raise ValueError("transaction is outside the adopted chain")
    return tx, block, proof


def receive(rpc, pins, policy, txid, vout, owner, units):
    """Full-node wallet using pinned deployment, chain data and public verifier only."""
    first_tip = rpc.call("getbestblockhash")
    tx, block, inclusion = confirmed(rpc, txid)
    funding, fund_block, _ = confirmed(rpc, pins["verifier_funding"])
    wire_funding = funding.txid_wire()
    if (pins["issuance_root"] != policy.root_txid[::-1].hex()
            or any(output.script != policy.lock for output in funding.outputs) or len(funding.outputs) != 2):
        raise ValueError("different approved verifier")
    if not 0 <= vout < len(tx.outputs) or token_state(tx.outputs[vout], wire_funding) != (units, owner):
        raise ValueError("wrong receipt outpoint or order")
    if len(tx.serialize()) == MINT_BYTES:
        root, root_block, _ = confirmed(rpc, pins["issuance_root"])
        source = tx.inputs[0]
        if (source.txid != root.txid_wire() or vout != 0
                or not 0 <= source.vout < len(ISSUANCE_AMOUNTS)
                or ISSUANCE_AMOUNTS[source.vout] != units):
            raise ValueError("unauthorized issuance outpoint")
        parents, heights = (root,), (root_block["height"],)
    else:
        actual = tx.inputs[0]
        if len(tx.serialize()) != PAYMENT_BYTES or actual.txid != wire_funding or actual.vout not in (0, 1):
            raise ValueError("missing actual proof-verifier input")
        opened = tuple(confirmed(rpc, item.txid[::-1].hex()) for item in tx.inputs[1:])
        parents = (funding, *(entry[0] for entry in opened))
        heights = (fund_block["height"], *(entry[1]["height"] for entry in opened))
    validate_at_heights(tx, parents, spend_height=block["height"], activation_height=2, utxo_heights=heights)
    coin = rpc.call("gettxout", txid, vout, True)
    if coin is None or coin["scriptPubKey"]["hex"] != tx.outputs[vout].script.hex():
        raise ValueError("receipt output is spent or unavailable")
    if rpc.call("getbestblockhash") != first_tip:
        raise ValueError("node tip changed during receipt verification")
    return tx, {
        "txid": txid, "vout": vout, "units": units, "owner": owner.hex(), "confirmations": coin["confirmations"],
        "blockhash": block["hash"], "height": block["height"], "merkle_index": inclusion.index,
        "merkle_header_hex": inclusion.header.hex(), "merkle_siblings_wire": [s.hex() for s in inclusion.siblings],
    }


def _mint(node, label, root, root_vout, funding, units, recipient, sign):
    draft = Transaction((Input(root.txid_wire(), root_vout),),
                        (token_output(funding.txid_wire(), units, recipient),), version=1)
    spent = root.outputs[root_vout]
    signature = sign(hash256(preimage_all(draft, 0, spent.value, spent.script))) + b"\x41"
    final = draft.with_script(0, push(signature))
    if len(final.serialize()) != MINT_BYTES:
        raise AssertionError("mint wire shape differs from proof profile")
    return node.include(label, final, (root,))


def _payment(funding, slot, parents, payouts):
    return Transaction((Input(funding.txid_wire(), slot),
                        *(Input(parent.txid_wire(), vout) for parent, vout in parents)),
                       tuple(token_output(funding.txid_wire(), q, who) for q, who in payouts), version=1)


def _signed(tx, policy, funding, parents, proof, sign):
    signed = tx.with_script(0, policy.verifier_witness(tx, funding, parents, proof))
    for vin, (parent, vout) in enumerate(parents, 1):
        signed = signed.with_script(vin, holder_witness(tx, vin, parent.outputs[vout], sign))
    if len(signed.serialize()) != PAYMENT_BYTES:
        raise AssertionError("payment wire shape differs from its own parent circuit")
    return signed


def _archive(node, stage, pins, summary):
    blocks, transactions = {}, {}
    for info in node.evidence["transactions"].values():
        tx, block, proof = confirmed(node.node, info["txid"])
        blocks[block["hash"]] = {"txids": block["tx"], "height": block["height"], "header": proof.header.hex()}
        transactions[info["txid"]] = tx.serialize().hex()
    with lzma.open(stage / "regtest.json.xz", "xt", preset=3) as stream:
        json.dump({"summary": summary, "recipient_policy": pins, "transactions": transactions, "blocks": blocks},
                  stream, separators=(",", ":"))


def run(node, prover, manifest, key, stage):
    rpc = node.node
    if (rpc.call("getconnectioncount") != 0 or rpc.call("getblockcount") != 0):
        raise ValueError("use a fresh unpeered BSV regtest with Chronicle activation at height 2")
    setup = node.setup(outputs=4, anchor_tag=b"BSV/CCTP/local-backtrace/2x2/v1")
    issuer, sign_mint = test_signer(13)
    issuer_lock = push(issuer) + asm("OP_CHECKSIG")
    root = node.include("issuance-root", Transaction((Input(setup.txid_wire(), 0),),
                        (Output(1_000_000, issuer_lock),) * 3, version=1), (setup,))
    policy = Policy(root.txid_wire(), key)
    funding = node.include("verifier-funding", Transaction((Input(setup.txid_wire(), 1),),
                           (Output(200_000, policy.lock),) * 2, version=1), (setup,))
    pins = {"issuance_root": root.txid(), "verifier_funding": funding.txid(),
            "verifier_lock_sha256": sha256(policy.lock).hexdigest(),
            "verifying_key_sha256": manifest["verifying_key_sha256"], "pin_height": rpc.call("getblockcount")}
    save(stage / "recipient-policy.json", pins)

    alice, sign_alice = test_signer(21)
    bob, sign_bob = test_signer(22)
    carol, _ = test_signer(23)
    mint_labels = ("alice-mint-1", "alice-mint-2", "bob-mint")
    mints = tuple(_mint(node, label, root, i, funding, ISSUANCE_AMOUNTS[i], who, sign_mint)
                  for i, (label, who) in enumerate(zip(mint_labels, (alice, alice, bob), strict=True)))
    foreign = node.include("foreign-root", Transaction((Input(setup.txid_wire(), 2),),
                           (Output(1_000_000, issuer_lock),), version=1), (setup,))
    copy = _mint(node, "copied-token", foreign, 0, funding, 300, alice, sign_mint)
    if copy.outputs != mints[0].outputs:
        raise AssertionError("expected a byte-for-byte token copy")
    del sign_mint

    wallet = lambda txid, who, value: receive(rpc, pins, policy, txid, 0, who, value)
    alice_inputs = tuple((wallet(mints[i].txid(), alice, ISSUANCE_AMOUNTS[i])[0], 0) for i in (0, 1))
    rejected = {}
    payments = {}
    alice_payouts = ((275, bob), (225, alice))
    first_proof, first_record = prover.prove("alice-to-bob", funding, alice_inputs, policy)
    first = _payment(funding, 0, alice_inputs, alice_payouts)
    inflated = replace(first, outputs=(token_output(funding.txid_wire(), 276, bob), first.outputs[1]))
    rejected["inflated_signed_outputs"] = node.reject(_signed(inflated, policy, funding, alice_inputs, first_proof, sign_alice))
    fake_inputs = ((copy, 0), alice_inputs[1])
    fake_proof, fake_record = prover.prove("valid-opening-for-unauthorized-source", funding, fake_inputs, policy)
    fake_spend = _payment(funding, 0, fake_inputs, alice_payouts)
    rejected["copied_token_with_valid_opening"] = {
        **fake_record, "rejection": node.reject(_signed(fake_spend, policy, funding, fake_inputs, fake_proof, sign_alice)),
    }
    first = node.include("alice-to-bob", _signed(first, policy, funding, alice_inputs, first_proof, sign_alice),
                         (funding, *(p for p, _ in alice_inputs)))
    first_from_chain, bob_receipt = wallet(first.txid(), bob, 275)
    bob_old, bob_origin = wallet(mints[2].txid(), bob, 150)
    bob_inputs = ((first_from_chain, 0), (bob_old, 0))
    second_proof, second_record = prover.prove("bob-to-carol", funding, bob_inputs, policy)
    second = _payment(funding, 1, bob_inputs, ((350, carol), (75, bob)))
    second = node.include("bob-to-carol", _signed(second, policy, funding, bob_inputs, second_proof, sign_bob),
                          (funding, *(p for p, _ in bob_inputs)))
    _, carol_receipt = wallet(second.txid(), carol, 350)
    try:
        wallet(first.txid(), bob, 275)
    except ValueError as error:
        if "spent or unavailable" not in str(error):
            raise
        rejected["already_spent_bob_receipt"] = str(error)
    else:
        raise AssertionError("wallet still accepts Bob's spent receipt")

    for label, tx, parents, proof in (("alice-to-bob", first, alice_inputs, first_record),
                                      ("bob-to-carol", second, bob_inputs, second_record)):
        raws = [p.serialize() for p, _ in parents]
        if len({p.txid() for p, _ in parents}) != 2 or any(raw in item.script for raw in raws for item in tx.inputs):
            raise AssertionError("expected two independent parents and zero embedded raw transactions")
        payments[label] = {
            **proof, "txid": tx.txid(),
            "direct_token_parents": [f"{p.txid()}:{vout}" for p, vout in parents],
            "direct_parent_bytes_private": list(map(len, raws)), "parent_raw_bytes_in_scripts": 0,
            "input_witness_bytes": [len(i.script) for i in tx.inputs], "tx_bytes": len(tx.serialize()),
            "proof_witness_bytes": PROOF_FIELDS * (PROOF_BYTES + 1),
        }
    funding_bytes = len(funding.serialize())
    summary = {
        "scope": "Bounded regtest proof-verifier funding with two one-time outputs and three exact anchor allowances.",
        "startup_seconds": prover.startup_seconds, "parameters": manifest, "payments": payments,
        "shared_verifier_funding_bytes": funding_bytes, "shared_verifier_lock_bytes": len(policy.lock),
        "total_funding_and_both_payments_bytes": funding_bytes + len(first.serialize()) + len(second.serialize()),
        "payment_byte_delta": len(second.serialize()) - len(first.serialize()),
        "receipts": {"bob": bob_receipt, "bob_old": bob_origin, "carol": carol_receipt}, "rejections": rejected,
        "confirmation_timings": node.confirmation_timings, **node.evidence,
    }
    _archive(node, stage, pins, summary)
    save(stage / "summary.json", summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--parameters", type=Path, required=True)
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.parameters / "manifest.json").read_text())
    if manifest.get("profile") != "parent-openings-2x2" or manifest.get("test_only") is not True:
        raise ValueError("expected test-only 2→2 parent opening parameters")
    key, _ = read_key(json.loads((args.parameters / "key.json").read_text()), "plain")
    args.out.mkdir()
    node = Regtest(args.node_url, args.cookie)
    with ParentProver(args.prover, args.parameters, manifest, args.out) as prover:
        run(node, prover, manifest, key, args.out)


if __name__ == "__main__":
    main()

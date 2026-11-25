"""Replay signed holder and ticket variants with verifyscript against archived, mined inputs."""
import argparse
from dataclasses import replace
import json
import lzma
from pathlib import Path

from inventory_payment import companion_witness, token_witness
from regtest_mint import Node
from run_inventory_wide_regtest import test_signer
from shared.script import push
from shared.transaction import Input, Transaction, hash256, preimage_all, preimage_otda
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE


class Replay:
    def __init__(self, node, fixtures, profile):
        self.node = node
        if node.call("getblockchaininfo")["chain"] != "regtest":
            raise ValueError("expected a regtest node")
        self.summary = json.loads((fixtures / f"inventory-{profile}-regtest-summary.json").read_text())
        with lzma.open(fixtures / f"inventory-{profile}-regtest.json.xz", "rt") as stream:
            self.raw = json.load(stream)["transactions"]
        self.records = self.summary["transactions"]
        self.by_txid = {r["txid"]: r for r in self.records.values()}

    def actual(self, label):
        return self.by_id(self.records[label]["txid"])

    def by_id(self, txid):
        tx = Transaction.parse(bytes.fromhex(self.raw[txid]))
        record = self.by_txid[txid]
        if tx.txid() != txid or self.node.call("getblockhash", record["height"]) != record["blockhash"]:
            raise ValueError("archived transaction or active confirming block mismatch")
        return tx

    def check(self, tx, vins, expected):
        encoded = tx.serialize().hex()
        queries = []
        for vin in vins:
            txin = tx.inputs[vin]
            txid = txin.txid[::-1].hex()
            spent = self.by_id(txid).outputs[txin.vout]
            queries.append(dict(tx=encoded, n=vin, reportflags=True,
                                txo=dict(lock=spent.script.hex(), value=spent.value, height=self.by_txid[txid]["height"])))
        results = self.node.call("verifyscript", queries, False, 20_000)
        if [row["result"] for row in results] != expected:
            raise AssertionError(f"unexpected node script results for {tx.txid()}: {results}")
        return {"candidate_txid": tx.txid(), "vin_results": [dict(vin=i, **row) for i, row in zip(vins, results, strict=True)]}


def compact_holder(replay):
    original = replay.actual("payment-1")
    companion = replay.actual("payment-1-companion")
    vin = 2
    txin = original.inputs[vin]
    previous = replay.by_id(txin.txid[::-1].hex()).outputs[txin.vout]
    origin = next(label for label, r in replay.records.items() if r["txid"] == txin.txid[::-1].hex())
    # The wide harness deliberately uses public fixture keys indexed by origin position.
    owner_sign = test_signer(1000 + int(origin.removeprefix("origin-")))[1]
    current = replace(original, locktime=1)
    full = preimage_all(current, vin, previous.value, previous.script)
    owner_sig = owner_sign(hash256(full))
    raw = preimage_all(current, vin, previous.value, COMPACT_SCRIPTCODE)
    stale = preimage_all(original, vin, previous.value, COMPACT_SCRIPTCODE)
    points = b"".join(item.outpoint() for item in current.inputs)
    other = replace(companion, locktime=2)
    fake = points[:36] + Input(other.txid_wire(), 0).outpoint() + points[72:]
    forged = raw[:4] + hash256(fake) + raw[36:]
    variants = (
        ("correct_reauthorization", owner_sig, companion, points, raw),
        ("previous_locktime_binding", owner_sig, companion, points, stale),
        ("wrong_holder", test_signer(42)[1](hash256(full)), companion, points, raw),
        ("holder_only_signed_compact_suffix", owner_sign(hash256(raw)), companion, points, raw),
        ("changed_companion", owner_sig, other, points, raw),
        ("changed_companion_and_internally_matching_prevouts", owner_sig, other, fake, forged),
    )
    checks = {}
    for label, signature, witness_parent, vector, candidate_preimage in variants:
        witness = b"".join(map(push, (signature + b"\x41", witness_parent.serialize(), vector, candidate_preimage)))
        expected = ["ok" if label == "correct_reauthorization" else "error"]
        checks[label] = replay.check(current.with_script(vin, witness), [vin], expected)
    return {"mined_transaction": replay.records["payment-1"], "actual_token": {"txid": txin.txid[::-1].hex(), "vout": txin.vout},
            "variant_locktime": current.locktime, "vin": vin, "results": checks}


def swapped_ticket(replay):
    original = replay.actual("first-selection")
    initial, alternate = (replay.actual(label + "-verifier") for label in ("first-selection", "second-selection"))
    companion = replay.actual("first-selection-companion")
    if initial.outputs != alternate.outputs or initial.txid() == alternate.txid():
        raise ValueError("expected distinct actual funding with identical verifier outputs")
    swapped = replace(original, inputs=(Input(alternate.txid_wire(), 0), *original.inputs[1:]))
    old = push(preimage_otda(original, 0, COMPACT_SCRIPTCODE, 0x61))
    if not original.inputs[0].script.endswith(old):
        raise ValueError("expected final compact Chronicle preimage in the verifier witness")
    new = push(preimage_otda(swapped, 0, COMPACT_SCRIPTCODE, 0x61))
    swapped = swapped.with_script(0, original.inputs[0].script[:-len(old)] + new)
    swapped = swapped.with_script(1, companion_witness(swapped, companion))
    for vin, key in ((2, 15), (3, 17)):
        txin = swapped.inputs[vin]
        previous = replay.by_id(txin.txid[::-1].hex()).outputs[txin.vout]
        swapped = swapped.with_script(vin, token_witness(swapped, vin, previous, companion, fixture_signer(key)[1]))
    return {"mined_transaction": replay.records["first-selection"],
            "original_verifier": initial.txid() + ":0", "substitute_verifier": alternate.txid() + ":0",
            "original": replay.check(original, range(4), ["ok"] * 4),
            "substituted": replay.check(swapped, range(4), ["ok", "error", "ok", "ok"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("narrow", "wide"):
        parser.add_argument(f"--{name}-node-url", required=True)
        parser.add_argument(f"--{name}-cookie", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).resolve().parents[1] / "fixtures")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    narrow = Node(args.narrow_node_url, args.narrow_cookie)
    wide = Node(args.wide_node_url, args.wide_cookie)
    result = {"scope": "Read-only Bitcoin SV Node verifyscript over the specified vin of archived regtest spends. "
                       "No variant was submitted or mined.",
              "nodes": {"narrow": narrow.call("getnetworkinfo")["subversion"], "wide": wide.call("getnetworkinfo")["subversion"]},
              "compact_holder": compact_holder(Replay(wide, args.fixtures, "e-compact")),
              "same_lock_other_verifier_outpoint": {
                  profile: swapped_ticket(Replay(narrow, args.fixtures, profile)) for profile in ("b", "c")}}
    with args.out.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

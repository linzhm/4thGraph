"""Measure subset membership alone, with the same funded lock for every selection."""

import argparse
import json
from pathlib import Path
from random import Random

from inventory_multipath import multipath_script, selection_witness
from inventory_tree import InventoryLeaf, InventoryState, inventory_root, multi_path
from run_recursive_mimo import Regtest
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256


def example_leaves(width, owner):
    scope = hash256(b"CCTP bounded inventory membership experiment")
    return tuple(
        InventoryLeaf(scope, hash256(i.to_bytes(4, "little")) + bytes(4), InventoryState(i + 1, 1000, owner))
        for i in range(width)
    )


def run(node):
    if node.node.call("getblockchaininfo")["chain"] != "regtest" or node.node.call("getconnectioncount"):
        raise ValueError("an isolated BSV regtest is required")
    leaves = example_leaves(128, node.owner_key)
    root = inventory_root(leaves)
    component = multipath_script(128, 64)
    lock = component + push(root) + asm("OP_EQUALVERIFY OP_DEPTH OP_0 OP_NUMEQUAL")
    selections = {
        "first64": tuple(range(64)),
        "alternating": tuple(range(0, 128, 2)),
        "seed42": tuple(sorted(Random(42).sample(range(128), 64))),
    }
    setup = node.setup(outputs=1)
    funding = node.include("membership-funding", Transaction(
        (Input(setup.txid_wire(), 0),), (Output(500_000, lock),) * len(selections)), (setup,))
    cases = {}
    for i, (label, positions) in enumerate(selections.items()):
        tx = Transaction((Input(funding.txid_wire(), i),), (Output(450_000, asm("OP_1")),))
        witness = selection_witness(leaves, positions)
        if i == 0:
            # Keep hidden siblings from the authentic tree, substitute one leaf digest.
            tampered = bytearray(witness)
            tampered[-1] ^= 1
            rejection = node.reject(tx.with_script(0, bytes(tampered)))
        final = node.include(label, tx.with_script(0, witness), (funding,))
        cases[label] = {
            "sibling_hash_bytes": 32 * len(multi_path(leaves, positions)), "selection_record_bytes": 64 * 33,
            "witness_bytes": len(witness), "transaction_bytes": len(final.serialize()),
            "timings": node.confirmation_timings[label],
        }
    return {
        "scope": "Subset membership component using synthetic outpoints and a fixed known root. "
                 "No CCTP source certificate, actual token inputs or balance check in these transactions.",
        "width": 128, "selected": 64, "root": root.hex(), "lock_bytes": len(lock),
        "funding_bytes_for_three_outputs": len(funding.serialize()), "changed_member_rejection": rejection,
        "selections": cases, **node.evidence,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(Regtest(args.node_url, args.cookie))
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")

"""Fund Script Lab templates and observe mempool and mining on a fresh peerless regtest."""
import argparse
from importlib import import_module
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import sleep

from fourthgraph.benchmark.run import PROJECTS, ROOT, dump_json
from fourthgraph.benchmark.cases import native_coin, payment
from fourthgraph.benchmark.validation import Node, RPCError, chain_metadata
from fourthgraph.bsv.transaction import Transaction

COIN_VALUE = 10_000_000
# Two canonical R1 outputs make an activation about 120 KB. Keep this
# fixture above the launcher's 0.5 sat/B mining floor even for activation.
SPEND_FEE = 250_000


def submit_and_mine(node, tx):
    txid = tx.txid()
    row = {"txid": txid, "bytes": len(tx.serialize())}
    try:
        accepted_id = node.call("sendrawtransaction", [tx.serialize().hex()])
    except RPCError as error:
        if error.code not in {-22, -25, -26, -27}:
            raise
        return {**row, "mempool": False, "mined": False,
                "rpc_code": error.code, "rpc_message": error.message}
    if accepted_id != txid or txid not in node.call("getrawmempool", []):
        raise ValueError("node returned success without recording the transaction in the mempool")
    for attempt in range(3):
        if attempt:
            sleep(1)
        block_hash, = node.call("generate", [1])
        block = node.call("getblock", [block_hash])
        if txid in block["tx"]:
            return {**row, "mempool": True, "mined": True, "block": block_hash, "height": block["height"]}
    mempool = node.call("getrawmempool", [True])
    return {**row, "mempool": True, "mined": False,
            "still_in_mempool": txid in mempool, "mempool_entry": mempool.get(txid),
            "blocks_checked": 3}


def admission_case(node, template, label, flag, scratch):
    coins = [template.create(f"{label}/{index}", COIN_VALUE) for index in range(2)]
    if template.deferred:
        sponsor = native_coin(label + "/sponsor", SPEND_FEE)
    else:
        sponsor = None
    deposits = [*coins, sponsor] if sponsor else coins
    unsigned = Transaction((), tuple(coin.output for coin in deposits))
    try:
        funded = node.call("fundrawtransaction", [
            unsigned.serialize().hex(), {"changePosition": len(deposits), "feeRate": 0.00002},
        ])
        signed = node.call("signrawtransaction", [funded["hex"]])
    except RPCError as error:
        if error.code not in {-22, -25, -26, -27} and not (
            error.code == -4 and "too large" in error.message.lower()
        ):
            raise
        return {"wallet_funding_error": {"code": error.code, "message": error.message}}
    if not signed["complete"]:
        raise ValueError("regtest wallet could not sign the funding transaction")
    tx = Transaction.parse(bytes.fromhex(signed["hex"]))
    if tx.outputs[:len(deposits)] != tuple(coin.output for coin in deposits):
        raise ValueError("regtest wallet changed the intended output")
    legs = {"funding": submit_and_mine(node, tx)}
    if not legs["funding"]["mined"]:
        return legs
    if sponsor:
        activation = payment([(tx, 0, coins[0], flag), (tx, 1, coins[1], flag), (tx, 2, sponsor, 0x41)],
                             [coin.activated for coin in coins], scratch, fee=SPEND_FEE)
        tx = activation.tx
        legs["activation"] = submit_and_mine(node, tx)
        if not legs["activation"]["mined"]:
            return legs
        coins = [coin.activated for coin in coins]
    destinations = [native_coin(f"{label}/exit/{index}", COIN_VALUE - SPEND_FEE // 2) for index in range(2)]
    exit_tx = payment([(tx, 0, coins[0], flag), (tx, 1, coins[1], flag)],
                      destinations, scratch, fee=SPEND_FEE)
    legs["exit"] = submit_and_mine(node, exit_tx.tx)
    return legs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", choices=PROJECTS)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    profile = os.environ.get("SCRIPT_LAB_REGTEST_PROFILE")
    if profile not in {"default", "raised"}:
        parser.error("run through tools/verify_node.sh --profile default or raised")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getconnectioncount", []) != 0:
        raise ValueError("admission requires a peerless regtest node")
    if node.call("getblockcount", []) == 0:
        node.call("generate", [101])
    meta = chain_metadata()
    if meta["commit"] != PROJECTS[args.project][0]:
        raise ValueError(f"unexpected chain-gang pin: {meta}")
    sys.path.insert(0, str(ROOT / "projects" / args.project / "reference"))
    templates = import_module("benchmark_adapter").TEMPLATES
    cases = {}
    with TemporaryDirectory(prefix="script-lab-admission-") as temp:
        for name, template in templates.items():
            for mode in (0x41, 0x61):
                label = f"{args.project}/{name}/{mode:02x}"
                cases[label] = admission_case(node, template, label, mode, Path(temp))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    dump_json(args.output, {"schema_version": 1, "profile": profile, "bsv_node_version": node.version,
                            "project": args.project, "chain_gang": meta,
                            "script_lab_commit": subprocess.check_output(
                                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                            ).strip(),
                            "common_consensus_options": {
                                "genesisactivationheight": 1, "chronicleactivationheight": 2,
                                "excessiveblocksize": 1_000_000_000, "maxstackmemoryusageconsensus": 100_000_000,
                            },
                            "minminingtxfee": "0.000005", "spend_fee_sats": SPEND_FEE, "cases": cases})


if __name__ == "__main__":
    main()

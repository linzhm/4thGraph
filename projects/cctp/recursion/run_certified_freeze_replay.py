"""Replay the archived v3 freeze and unfreeze controls on isolated BSV regtest."""

import argparse
from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
from http.client import IncompleteRead, RemoteDisconnected
import json
import lzma
from pathlib import Path
from time import sleep
from urllib.error import URLError

from continuity_statement import ParentReceipt
from operational_token import TokenPolicy
from regtest_mint import Node
from shared.transaction import Transaction, hash256
from test_operational_token import fixture_signer

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ARCHIVE = FIXTURES / "v3-certified-cross-chain-regtest.json.xz"
ARCHIVE_SHA256 = "19174d15a3643369cbd12658cc41ba79c03a0d1a2ec57bce6aa4ee446190e025"
REGTEST_MAGIC = bytes.fromhex("fabfb5da")
BEFORE_FREEZE, FROZEN, UNFROZEN = 324, 325, 327
TRANSIENT_RPC = (IncompleteRead, RemoteDisconnected, ConnectionError, TimeoutError, URLError, json.JSONDecodeError)
READ_DELAYS = (0, 0.2, 0.6, 1.5)


def read(node, method, *params):
    for delay in READ_DELAYS:
        if delay:
            sleep(delay)
        try:
            return node.call(method, *params)
        except TRANSIENT_RPC:
            if delay == READ_DELAYS[-1]:
                raise


def index_blocks(paths):
    """Index complete regtest frames from published blk files without touching chainstate."""
    saved = {}
    for path in paths:
        with path.open("rb") as stream:
            end = path.stat().st_size
            while stream.tell() + 8 <= end:
                fields = stream.read(8)
                if fields == bytes(8):
                    break
                size = int.from_bytes(fields[4:], "little")
                position = stream.tell()
                if fields[:4] != REGTEST_MAGIC or size < 81:
                    raise ValueError(f"invalid regtest block frame in {path} at offset {position - 8}")
                if position + size > end:
                    break
                header = stream.read(80)
                saved[hash256(header)[::-1].hex()] = path, position, size
                stream.seek(position + size)
    return saved


def source_block(source, blockhash, block_files):
    located = block_files.get(blockhash)
    if located is None:
        raw = bytes.fromhex(read(source, "getblock", blockhash, 0))
    else:
        path, position, size = located
        with path.open("rb") as stream:
            stream.seek(position)
            raw = stream.read(size)
        if len(raw) != size:
            raise ValueError("source block file changed during reading")
    if len(raw) < 81 or hash256(raw[:80])[::-1].hex() != blockhash:
        raise ValueError("raw block does not match the source active-chain hash")
    return raw


def replay_until(source, target, height, block_files):
    tip = read(target, "getblockchaininfo")
    if tip["bestblockhash"] != read(source, "getblockhash", tip["blocks"]):
        raise ValueError("isolated node must be on the exact source-chain prefix")
    for current in range(tip["blocks"] + 1, height + 1):
        blockhash = read(source, "getblockhash", current)
        raw = source_block(source, blockhash, block_files)
        for delay in READ_DELAYS:
            if delay:
                sleep(delay)
            try:
                result = target.call("submitblock", raw.hex())
            except TRANSIENT_RPC:
                if read(target, "getbestblockhash") == blockhash:
                    break
                if delay == READ_DELAYS[-1]:
                    raise
                continue
            if result is not None and read(target, "getbestblockhash") != blockhash:
                raise ValueError(f"isolated node refused original block {current}: {result}")
            break
        if read(target, "getbestblockhash") != blockhash:
            raise ValueError(f"isolated node failed to adopt original block {current}")
    return read(target, "getblockcount")


def archive_material():
    if sha256(ARCHIVE.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("unexpected v3 archive bytes")
    with lzma.open(ARCHIVE, "rt") as stream:
        archive = json.load(stream)
    records = archive["summary"]["transactions"]
    labels = ("split", "funding-freeze-640", "freeze-640", "unfreeze-640")
    transactions = {}
    for label in labels:
        tx = Transaction.parse(bytes.fromhex(archive["transactions"][label]))
        if tx.txid() != records[label]["txid"]:
            raise ValueError(f"archive transaction does not match its receipt: {label}")
        transactions[label] = tx
    return transactions, records


def check_live(node, tx, vout):
    actual = read(node, "gettxout", tx.txid(), vout, False)
    output = tx.outputs[vout]
    if (actual is None or actual["scriptPubKey"]["hex"] != output.script.hex()
            or Decimal(str(actual["value"])) * 100_000_000 != output.value):
        raise ValueError("verified chain UTXO differs from the archived output")


def exercise(source, target, block_files):
    txs, records = archive_material()
    if source.url == target.url or read(target, "getconnectioncount") or read(target, "getblockcount") > BEFORE_FREEZE:
        raise ValueError("use a separate unpeered replay node at or below the pre-freeze block")
    for label, height in (("funding-freeze-640", BEFORE_FREEZE), ("freeze-640", FROZEN), ("unfreeze-640", UNFROZEN)):
        if read(source, "getblockhash", height) != records[label]["blockhash"]:
            raise ValueError("source active chain does not match the archived v3 lifecycle")
    split, funding, frozen, unfrozen = (
        txs[label] for label in ("split", "funding-freeze-640", "freeze-640", "unfreeze-640")
    )
    replay_until(source, target, BEFORE_FREEZE, block_files)
    check_live(target, split, 0)
    check_live(target, split, 1)
    check_live(target, funding, 0)
    policy = TokenPolicy((funding.outputs[0].script,), fixture_signer(12)[0], certified_admin=True)
    prior = policy.parse(split.outputs[0].script)
    after = policy.parse(frozen.outputs[0].script)
    restored = policy.parse(unfrozen.outputs[0].script)
    if (prior is None or prior.frozen or prior.quantity != 640 or after != replace(prior, frozen=True)
            or restored != prior or len({tx.outputs[0].value for tx in (split, frozen, unfrozen)}) != 1):
        raise ValueError("archive does not preserve the actual token state and satoshis")

    checked = []
    for tx, spent, height in ((frozen, split, FROZEN), (unfrozen, frozen, UNFROZEN)):
        if tx.inputs[0].txid != spent.txid_wire() or tx.inputs[0].vout != 0:
            raise ValueError("archive does not pair the actual consumed vout")
        replay_until(source, target, height, block_files)
        check_live(target, tx, 0)
        check_live(target, split, 1)
        if read(target, "gettxout", spent.txid(), 0, False) is not None:
            raise ValueError("replayed administration block did not consume its original outpoint")
        blockhash = read(target, "getblockhash", height)
        if tx.txid() not in read(target, "getblock", blockhash, 1)["tx"]:
            raise ValueError("replayed block does not contain the archived administration transaction")
        checked.append({
            "height": height, "blockhash": blockhash, "txid": tx.txid(),
            "consumed_txid": spent.txid(), "consumed_vout": 0, "successor_vout": 0,
            "satoshis": tx.outputs[0].value, "quantity": prior.quantity, "frozen": height == FROZEN,
            "receipt_parents": [item.hex() for item in ParentReceipt.parse(tx.outputs[1]).parents],
        })
    return {
        "scope": "Archived v3 blocks replayed and consensus-validated by an isolated Bitcoin SV regtest",
        "node": read(target, "getnetworkinfo")["subversion"],
        "asset_id": prior.asset_id.hex(), "owner": prior.owner.hex(), "archive_sha256": ARCHIVE_SHA256,
        "paired_successors": checked,
        "independent_unchanged_output": {"txid": split.txid(), "vout": 1, "quantity": 384},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--source-cookie", type=Path, required=True)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--source-block-file", action="append", type=Path, default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("use a new output path")
    result = exercise(Node(args.source_url, args.source_cookie), Node(args.node_url, args.cookie),
                      index_blocks(args.source_block_file))
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

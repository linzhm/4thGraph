"""Archive mined inventory transactions, immediate funding and the original test-proof artifacts."""
import argparse
from hashlib import sha256
import json
import lzma
from pathlib import Path

from regtest_mint import Node
from shared.transaction import Transaction


def archive(node, run_dir, output):
    summary = json.loads((run_dir / "summary.json").read_text())
    if node.call("getblockchaininfo")["chain"] != "regtest":
        raise ValueError("expected local regtest evidence")
    records = {}
    sources = set()
    for label, record in summary["transactions"].items():
        txid = record["txid"]
        data = node.call("getrawtransaction", txid, True)
        raw = data["hex"]
        transaction = Transaction.parse(bytes.fromhex(raw))
        if (transaction.txid() != txid or len(bytes.fromhex(raw)) != record["bytes"]
                or node.call("getblockhash", record["height"]) != record["blockhash"]
                or data["blockhash"] != record["blockhash"]):
            raise ValueError(f"unconfirmed or inconsistent record {label}")
        records[txid] = raw
        sources.update(item.txid[::-1].hex() for item in transaction.inputs)
    # Include the coinbase funding the disposable issuance origin for a complete local replay.
    funding = {}
    for txid in sorted(sources - records.keys()):
        raw = node.call("getrawtransaction", txid)
        if Transaction.parse(bytes.fromhex(raw)).txid() != txid:
            raise ValueError("funding transaction hash mismatch")
        funding[txid] = raw
    artifacts = {path.name: path.read_bytes() for path in sorted(run_dir.glob("*-proof.json"))}
    expected = {record["artifact_sha256"] for record in summary.get("certificates", {}).values()
                if "artifact_sha256" in record}
    expected.update(row["payment_proof"]["artifact_sha256"] for row in summary["payments"]
                    if row.get("payment_proof"))
    if {sha256(data).hexdigest() for data in artifacts.values()} != expected:
        raise ValueError("native proof artifacts differ from the recorded digests")
    evidence = {"profile": summary["profile"], "scope": summary["scope"], "transactions": records,
                "funding": funding, "proof_artifacts": {k: b.decode() for k, b in artifacts.items()}}
    with lzma.open(output, "xt", encoding="utf8") as stream:
        json.dump(evidence, stream, separators=(",", ":"))
    return len(records), len(artifacts), output.stat().st_size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", required=True, type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    print(archive(Node(args.node_url, args.cookie), args.run_dir, args.out))


if __name__ == "__main__":
    main()

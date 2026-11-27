"""Check the transaction outpoints, byte counts, and lock hashes in the public comparison."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from time import sleep
from urllib.error import HTTPError
from urllib.request import urlopen

from fourthgraph.bsv.transaction import Transaction, blob


PROJECT = Path(__file__).resolve().parents[1]


def download(url):
    for retry_delay in (3, 7, 15, None):
        try:
            with urlopen(url, timeout=60) as response:
                return bytes.fromhex(response.read().decode("ascii"))
        except HTTPError as error:
            if retry_delay is None or error.code not in (429, 502, 503, 504):
                raise
            delay = error.headers.get("Retry-After", "")
            sleep(min(int(delay), 30) if delay.isdecimal() else retry_delay)


def read_raw(network, txid, cache):
    path = cache / network / f"{txid}.hex"
    if path.is_file():
        raw = bytes.fromhex(path.read_text(encoding="ascii"))
    else:
        raw = download(f"https://api.whatsonchain.com/v1/bsv/{network}/tx/{txid}/hex")
    transaction = Transaction.parse(raw)
    if transaction.txid() != txid:
        raise ValueError(f"transaction hash does not match {txid}")
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw.hex() + "\n", encoding="ascii")
    return transaction, len(raw)


def measure(row, cache):
    deployment, deployment_bytes = read_raw(row["network"], row["lock_txid"], cache)
    lock = deployment.outputs[row["output"]].script
    measured = dict(deployment_tx_bytes=deployment_bytes, lock_bytes=len(lock), lock_sha256=sha256(lock).hexdigest())
    if "spend_txid" in row:
        spend, spend_bytes = read_raw(row["network"], row["spend_txid"], cache)
        txin = spend.inputs[row["input"]]
        if (txin.txid, txin.vout) != (bytes.fromhex(row["lock_txid"])[::-1], row["output"]):
            raise ValueError("the recorded spend does not reference the lock outpoint")
        measured.update(spend_tx_bytes=spend_bytes, unlock_bytes=len(txin.script),
                        path_bytes=len(blob(lock)) + len(blob(txin.script)),
                        funded_path_bytes=deployment_bytes + spend_bytes)
    return measured


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--cache", type=Path, default=PROJECT / "workspace/build/public-comparison")
    args = cli.parse_args()
    evidence = PROJECT / "versions/v0.13.0/public-comparison.json"
    for label, row in json.loads(evidence.read_bytes()).items():
        measured = measure(row, args.cache)
        expected = {key: row[key] for key in measured}
        if measured != expected:
            raise ValueError(f"{label} byte counts or hashes differ: {measured}")
        print(f"{label}: {measured}")


if __name__ == "__main__":
    main()

"""Measure transaction costs directly from finalized wire serialization."""


def measure_transaction(tx):
    unlocking = [len(item.script) for item in tx.inputs]
    locking = [len(item.script) for item in tx.outputs]
    size = len(tx.serialize())
    return {"txid": tx.txid(), "bytes": size, "locking_bytes": sum(locking),
            "unlocking_bytes": sum(unlocking), "non_script_bytes": size - sum(locking) - sum(unlocking),
            "input_script_bytes": unlocking, "output_script_bytes": locking}


def measure_bundle(**groups):
    rows = {name: [measure_transaction(tx) for tx in transactions] for name, transactions in groups.items()}
    entries = [entry for group in rows.values() for entry in group]
    if len({entry["txid"] for entry in entries}) != len(entries):
        raise ValueError("count each transaction only once in a cost bundle")
    totals = {key: sum(entry[key] for entry in entries)
              for key in ("bytes", "locking_bytes", "unlocking_bytes", "non_script_bytes")}
    return {"groups": rows, "total": totals}

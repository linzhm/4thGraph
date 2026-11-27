"""Run a registered formula inside a complete synthetic spend."""

from hashlib import sha256
from importlib.metadata import PackageNotFoundError

from fourthgraph.bsv.script import asm, number
from fourthgraph.bsv.transaction import Input, Output, Transaction
from .validation import CONTEXT_PIN, chain_metadata


SPEND_FIXTURES = ("square",)
CONTEXT = {"spend_height": 4, "activation_height": 10, "utxo_heights": (3,)}
TX_VERSION = 1


def spend_profile(fixture):
    if fixture.name not in SPEND_FIXTURES:
        raise ValueError(f"{fixture.name} has no registered spend fixture")
    try:
        engine = chain_metadata()
    except PackageNotFoundError as exc:
        raise ValueError(f"spend evaluation requires pinned chain-gang {CONTEXT_PIN}") from exc
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError(f"spend evaluation requires pinned chain-gang {CONTEXT_PIN}")
    return {"fixture": "square-output-check/1", "engine": "chain-gang", **engine,
            "context": CONTEXT, "transaction_version": TX_VERSION}


def _verdict(validate, transaction, parent):
    try:
        validate(transaction, (parent,), **CONTEXT)
        return "accepted", None
    except (ValueError, RuntimeError) as exc:
        return "rejected", str(exc)


def check_spends(fixture, script):
    from fourthgraph.bsv.chain_gang import validate_at_heights

    cases = []
    max_bytes = {}
    for (operand,), (expected,) in fixture.vectors():
        lock = asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY") + script + number(expected) + asm("OP_EQUAL")
        parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),), version=TX_VERSION)
        spend = Transaction((Input(parent.txid_wire(), 0, number(operand)),),
                            (Output(9_000, asm("OP_1")),), version=TX_VERSION)
        # Use a different in-range operand but the same prevout and transaction fields.
        wrong_operand = (operand + 1) % 11
        rejected_spend = spend.with_script(0, number(wrong_operand))
        for transaction, required in ((spend, "accepted"), (rejected_spend, "rejected")):
            observed, detail = _verdict(validate_at_heights, transaction, parent)
            if observed != required:
                return {"status": "failed", "cases": cases, "operand": operand, "txid": transaction.txid(),
                        "expected": required, "observed": observed,
                        "diagnostic": detail or "spend fixture verdict differs from the oracle"}
        parent_bytes = len(parent.serialize())
        spend_bytes = len(spend.serialize())
        sizes = {"lock_script_bytes": len(lock), "witness_script_bytes": len(spend.inputs[0].script),
                 "funding_transaction_bytes": parent_bytes, "transaction_bytes": spend_bytes,
                 "path_bytes": parent_bytes + spend_bytes}
        for name, size in sizes.items():
            max_bytes[name] = max(max_bytes.get(name, 0), size)
        cases.append({"operand": operand, "expected": expected, "rejected_operand": wrong_operand,
                      "lock_sha256": sha256(lock).hexdigest(),
                      "parent_txid": parent.txid(), "accepted_txid": spend.txid(),
                      "rejected_txid": rejected_spend.txid(), "bytes": sizes})
    return {"status": "passed", "accepted": len(cases), "rejected": len(cases), "max_bytes": max_bytes, "cases": cases}

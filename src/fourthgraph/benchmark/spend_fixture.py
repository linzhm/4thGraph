"""Run a registered formula inside a complete synthetic spend."""

from hashlib import sha256
from importlib.metadata import PackageNotFoundError

from fourthgraph.bsv.script import asm, number
from fourthgraph.bsv.transaction import Input, Output, Transaction
from .validation import CONTEXT_PIN, chain_metadata


CONTEXT = {"spend_height": 4, "activation_height": 10, "utxo_heights": (3,)}
TX_VERSION = 1


def _wrong_square(operands):
    x, = operands
    return ((x + 1) % 11,)


def _wrong_bezier(operands):
    p0, p1, p2, t = operands
    if t in (0, 16):
        # Endpoints are independent of p1, but the tangent changes.
        return p0, p1 - 1 if p1 == 127 else p1 + 1, p2, t
    if max(p0, p1, p2) < 127:
        # A common translation changes the position and preserves the tangent.
        return p0 + 1, p1 + 1, p2 + 1, t
    # Away from t=16, any change to p0 changes the position.
    return p0 - 1 if p0 == 127 else p0 + 1, p1, p2, t


SPEND_FIXTURES = {"square": _wrong_square, "bezier": _wrong_bezier}


def spend_profile(fixture):
    if fixture.name not in SPEND_FIXTURES:
        raise ValueError(f"{fixture.name} has no registered spend fixture")
    try:
        engine = chain_metadata()
    except PackageNotFoundError as exc:
        raise ValueError(f"spend evaluation requires pinned chain-gang {CONTEXT_PIN}") from exc
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError(f"spend evaluation requires pinned chain-gang {CONTEXT_PIN}")
    return {"fixture": f"{fixture.name}-output-check/1", "engine": "chain-gang", **engine,
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
    wrong_inputs = SPEND_FIXTURES[fixture.name]
    for operands, expected in fixture.vectors():
        depth = asm("OP_DEPTH") + number(len(operands)) + asm("OP_NUMEQUALVERIFY")
        checks = b"".join(number(item) + asm("OP_EQUALVERIFY") for item in reversed(expected[1:]))
        lock = depth + script + checks + number(expected[0]) + asm("OP_EQUAL")
        parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),), version=TX_VERSION)
        witness = b"".join(map(number, operands))
        spend = Transaction((Input(parent.txid_wire(), 0, witness),),
                            (Output(9_000, asm("OP_1")),), version=TX_VERSION)
        # Replace only the witness with different in-range inputs.
        wrong = wrong_inputs(operands)
        if fixture.name == "square":
            case = {"operand": operands[0], "expected": expected[0], "rejected_operand": wrong[0]}
        else:
            case = {"operands": operands, "expected_outputs": expected, "rejected_operands": wrong}
        rejected_spend = spend.with_script(0, b"".join(map(number, wrong)))
        for transaction, required in ((spend, "accepted"), (rejected_spend, "rejected")):
            observed, detail = _verdict(validate_at_heights, transaction, parent)
            if observed != required:
                return {"status": "failed", "cases": cases, **case, "txid": transaction.txid(),
                        "expected": required, "observed": observed,
                        "diagnostic": detail or "spend fixture verdict differs from the oracle"}
        parent_bytes = len(parent.serialize())
        spend_bytes = len(spend.serialize())
        sizes = {"lock_script_bytes": len(lock), "witness_script_bytes": len(spend.inputs[0].script),
                 "funding_transaction_bytes": parent_bytes, "transaction_bytes": spend_bytes,
                 "path_bytes": parent_bytes + spend_bytes}
        for name, size in sizes.items():
            max_bytes[name] = max(max_bytes.get(name, 0), size)
        cases.append({**case, "lock_sha256": sha256(lock).hexdigest(),
                      "parent_txid": parent.txid(), "accepted_txid": spend.txid(),
                      "rejected_txid": rejected_spend.txid(), "bytes": sizes})
    return {"status": "passed", "accepted": len(cases), "rejected": len(cases), "max_bytes": max_bytes, "cases": cases}

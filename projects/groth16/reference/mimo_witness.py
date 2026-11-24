"""Serialize an authenticated token projection for the bounded Circom relation."""

from dataclasses import dataclass

MAX_QUANTITY = 2**64 - 1


@dataclass(frozen=True)
class MimoInput:
    outpoint: bytes
    amount: int


def witness(inputs, outputs, max_inputs, max_outputs):
    """Keep actual transaction order outside this sorted input projection."""
    if not 0 < len(inputs) <= max_inputs or not 0 < len(outputs) <= max_outputs:
        raise ValueError("transfer exceeds circuit capacity or has no token inputs or outputs")
    for item in inputs:
        if len(item.outpoint) != 36:
            raise ValueError("expected a 36-byte outpoint")
    for amount in (*(item.amount for item in inputs), *outputs):
        if type(amount) is not int or not 0 < amount <= MAX_QUANTITY:
            raise ValueError("expected a positive uint64 token amount")
    ordered = sorted(inputs, key=lambda item: item.outpoint)
    if len({item.outpoint for item in ordered}) != len(ordered):
        raise ValueError("duplicate token outpoint")

    total_in = sum(item.amount for item in ordered)
    total_out = sum(outputs)
    if total_in != total_out or total_in > MAX_QUANTITY:
        raise ValueError("token quantities do not conserve within uint64")

    amounts = [item.amount for item in ordered]
    high = [int.from_bytes(item.outpoint[:18], "big") for item in ordered]
    low = [int.from_bytes(item.outpoint[18:], "big") for item in ordered]

    def encode_padded(values, capacity):
        return list(map(str, values)) + ["0"] * (capacity - len(values))

    return {
        "inputTotal": str(total_in),
        "outputTotal": str(total_out),
        "inputAmount": encode_padded(amounts, max_inputs),
        "inputHigh": encode_padded(high, max_inputs),
        "inputLow": encode_padded(low, max_inputs),
        "outputAmount": encode_padded(outputs, max_outputs),
    }

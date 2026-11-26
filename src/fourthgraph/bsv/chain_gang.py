"""Complete-input checks with an explicitly selected chain-gang build."""

from tx_engine import Tx


def engine_transaction(transaction):
    raw = transaction.serialize()
    parsed = Tx.parse(raw)
    if parsed.serialize() != raw:
        raise AssertionError('chain-gang wire serialization differs')
    return parsed


def validate_at_heights(transaction, parents, *, spend_height, activation_height, utxo_heights):
    """Validate in consensus mode, using each input's recorded creation height."""
    heights = [
        (txin.txid[::-1].hex(), txin.vout, height)
        for txin, height in zip(transaction.inputs, utxo_heights, strict=True)
    ]
    spend = engine_transaction(transaction)
    funding = [engine_transaction(parent) for parent in parents]
    spend.validate_with_chronicle_context(funding, spend_height, activation_height, heights, True)

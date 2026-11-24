"""Bind an external SLH-DSA-SHA2-128s signature to a BSV input."""

from script import COMPANION_CODE, ORDINARY_CODE, locking_script
from shared.spend_authorization import DEFAULT_SIGHASH, SpendAuthorization, prepare_authorization
from shared.transaction import Input, Transaction, amount
from slh import verify


def authorization(tx, index, previous_amount, sighash=DEFAULT_SIGHASH) -> SpendAuthorization:
    return prepare_authorization(
        tx, index, previous_amount, sighash,
        ordinary_code=ORDINARY_CODE, companion_code=COMPANION_CODE,
    )


def current_input_unlock(auth, public_key, signature):
    if not verify(public_key, auth.checked_digest(), signature):
        raise ValueError('invalid SLH-DSA signature from external signer')
    return auth.witness(signature)


def sign_spend(tx, index, funding_raw, public_key, signer, *, sighash=DEFAULT_SIGHASH):
    """Verify the funding template before calling signer(message32).

    The caller authenticates the funding transaction and approves the intent.
    The signer uses pure SLH-DSA with the empty context on the supplied message.
    """
    if not 0 <= index < len(tx.inputs):
        raise ValueError('input index out of range')
    funding = Transaction.parse(funding_raw)
    current = tx.inputs[index]
    if current.txid != funding.txid_wire() or not 0 <= current.vout < len(funding.outputs):
        raise ValueError('funding outpoint mismatch')
    if current.script:
        raise ValueError('current input already has an unlocking script')
    if not tx.outputs:
        raise ValueError('payment requires outputs')
    tx.serialize()
    previous = funding.outputs[current.vout]
    if previous.script != locking_script(public_key):
        raise ValueError('funding output does not match public key and canonical template')
    auth = authorization(tx, index, previous.value, sighash)
    signature = signer(auth.checked_digest())
    return tx.with_script(index, current_input_unlock(auth, public_key, signature))


def sign_payment(funding_raw, vout, outputs, fee, public_key, signer, *, sighash=DEFAULT_SIGHASH):
    """Construct a one-input payment with the specified outputs and fee."""
    funding = Transaction.parse(funding_raw)
    if not 0 <= vout < len(funding.outputs):
        raise ValueError('invalid funding output')
    amount(fee)
    outputs = tuple(outputs)
    if not outputs:
        raise ValueError('payment requires outputs')
    if sum(output.value for output in outputs) + fee != funding.outputs[vout].value:
        raise ValueError('outputs plus fee must equal input value')
    tx = Transaction((Input(funding.txid_wire(), vout),), outputs)
    return sign_spend(tx, 0, funding_raw, public_key, signer, sighash=sighash)

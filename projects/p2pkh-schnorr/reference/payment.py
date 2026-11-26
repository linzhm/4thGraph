"""Build and authorize Schnorr spends with an external BIP340 signer."""

from bip340 import lift_x, to_bytes, verify
from schnorr_script import authorization_codes, compile_unlock, lock_for_owner, owner_hash, recognize
from shared.spend_authorization import DEFAULT_SIGHASH, prepare_authorization
from shared.transaction import CHRONICLE, SIGHASH_SINGLE, SIGHASH_TYPES, Input, Transaction, amount


def lock_for_public_key(public_key):
    if lift_x(public_key) is None:
        raise ValueError("invalid BIP340 public key")
    return lock_for_owner(owner_hash(public_key))


def sign_spend(tx, index, funding_raw, public_key, signer, *, sighash=DEFAULT_SIGHASH, chronicle_active=False):
    """Request one signature over the approved BSV digest from signer(message32)."""
    if type(index) is not int or not 0 <= index < len(tx.inputs):
        raise ValueError("input index out of range")
    current = tx.inputs[index]
    funding = Transaction.parse(funding_raw)
    if current.txid != funding.txid_wire() or not 0 <= current.vout < len(funding.outputs):
        raise ValueError("select an unsigned input matching the funding outpoint")
    return sign_previous(tx, index, funding.outputs[current.vout], public_key, signer,
                         sighash=sighash, chronicle_active=chronicle_active)


def sign_previous(tx, index, previous, public_key, signer, *, sighash=DEFAULT_SIGHASH, chronicle_active=False):
    """Sign a prepared input after its outpoint and previous output are matched."""
    if type(index) is not int or not 0 <= index < len(tx.inputs) or tx.inputs[index].script:
        raise ValueError("select an unsigned input")
    if type(sighash) is not int or sighash not in SIGHASH_TYPES:
        raise ValueError("unsupported sighash")
    if sighash & CHRONICLE and chronicle_active is not True:
        raise ValueError("Chronicle authorization requires an active spend context")
    if not tx.outputs:
        raise ValueError("payment requires outputs")
    if sighash & 31 == SIGHASH_SINGLE and index >= len(tx.outputs):
        raise ValueError("Schnorr wallet SINGLE requires a same-index output")

    point = lift_x(public_key)
    if point is None or recognize(previous.script) != owner_hash(public_key):
        raise ValueError("funding output does not match the BIP340 key and template")
    tx.serialize()

    ordinary_code, companion_code = authorization_codes()
    auth = prepare_authorization(tx, index, previous.value, sighash,
                                 ordinary_code=ordinary_code, companion_code=companion_code)
    message = auth.checked_digest()
    signature = signer(message)
    if not verify(public_key, message, signature):
        raise ValueError("invalid BIP340 signature from external signer")

    nonce_point = lift_x(signature[:32])
    unlock = compile_unlock(auth.preimage, auth.companion, public_key, to_bytes(point[1]),
                            signature, to_bytes(nonce_point[1]))
    return tx.with_script(index, unlock)


def sign_payment(funding_raw, vout, outputs, fee, public_key, signer):
    """Build a version-2 single-input ForkID ALL payment with an approved fee."""
    funding = Transaction.parse(funding_raw)
    if type(vout) is not int or not 0 <= vout < len(funding.outputs):
        raise ValueError("funding output index out of range")
    amount(fee)
    outputs = tuple(outputs)
    if not outputs or sum(output.value for output in outputs) + fee != funding.outputs[vout].value:
        raise ValueError("payment outputs and approved fee do not balance")
    tx = Transaction((Input(funding.txid_wire(), vout),), outputs)
    return sign_spend(tx, 0, funding_raw, public_key, signer)

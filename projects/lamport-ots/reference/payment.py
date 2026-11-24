"""Transaction authorization using an external Lamport signer callback."""
from dataclasses import dataclass

from script import COMPANION_CODE, ORDINARY_CODE, N, R, legacy_locking_script, locking_script
from lamport import verify_digest
from shared.script import number, push
from shared.transaction import (
    CHRONICLE, FORKID, SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_TYPES,
    Input, Transaction, amount, hash256, preimage_forkid, preimage_otda,
)

DEFAULT_SIGHASH = FORKID | SIGHASH_ALL


@dataclass(frozen=True)
class SpendAuthorization:
    requested_type: int
    preimage: bytes
    companion: bool
    legacy: bool

    def digest(self):
        return hash256(self.preimage)


def authorization(tx, index, previous_amount, sighash=DEFAULT_SIGHASH, *, legacy=False):
    if type(sighash) is not int or sighash not in SIGHASH_TYPES or not 0 <= index < len(tx.inputs):
        raise ValueError('unsupported sighash or input index')
    if legacy and sighash != DEFAULT_SIGHASH:
        raise ValueError('legacy output supports only ForkID ALL')
    amount(previous_amount)
    companion = bool(sighash & CHRONICLE) and sighash & 31 == SIGHASH_SINGLE and index >= len(tx.outputs)
    code = b'\xac' if legacy else COMPANION_CODE if companion else ORDINARY_CODE
    if sighash & CHRONICLE and not companion:
        preimage = preimage_otda(tx, index, code, sighash)
    else:
        preimage = preimage_forkid(tx, index, previous_amount, code, sighash & ~CHRONICLE)
    return SpendAuthorization(sighash, preimage, companion, legacy)


def _checked_digest(auth):
    digest = auth.digest()
    if (int.from_bytes(digest, 'big')+R) % N == 0:
        raise ValueError('degenerate binding digest; rebuild before signing')
    return digest


def current_input_unlock(auth, public_key, signature):
    if not verify_digest(public_key, _checked_digest(auth), signature):
        raise ValueError('invalid Lamport signature from external signer')
    witness = push(auth.preimage) + push(signature)
    if auth.legacy:
        return witness
    return witness + number(int(auth.companion))


def sign_spend(tx, index, funding_raw, public_key, signer, *, sighash=DEFAULT_SIGHASH):
    """Authorize a prepared input. signer(digest32) returns a packed 8192-byte signature.

    The caller authenticates funding, approves the transaction and requested mode,
    and supplies an external signer that persists one-time key consumption before
    disclosure. The callback is invoked once after preflight; it is never retried.
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
    universal = locking_script(public_key)
    legacy = legacy_locking_script(public_key)
    if previous.script not in (universal, legacy):
        raise ValueError('funding output does not match public key and canonical template')
    own_scripts = (universal, legacy, locking_script(public_key, transaction=False))
    if any(output.script in own_scripts for output in tx.outputs):
        raise ValueError('change must use a fresh Lamport key')
    auth = authorization(tx, index, previous.value, sighash, legacy=previous.script == legacy)
    signature = signer(_checked_digest(auth))
    return tx.with_script(index, current_input_unlock(auth, public_key, signature))


def sign_payment(funding_raw, vout, outputs, fee, public_key, signer, *, sighash=DEFAULT_SIGHASH):
    """Construct a single-input spend with approved outputs and fee."""
    funding = Transaction.parse(funding_raw)
    if not 0 <= vout < len(funding.outputs):
        raise ValueError('invalid funding output')
    amount(fee)
    outputs = tuple(outputs)
    if not outputs:
        raise ValueError('payment requires outputs')
    if sum(output.value for output in outputs)+fee != funding.outputs[vout].value:
        raise ValueError('outputs plus fee must equal input value')
    tx = Transaction((Input(funding.txid_wire(), vout),), outputs)
    return sign_spend(tx, 0, funding_raw, public_key, signer, sighash=sighash)

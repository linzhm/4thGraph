"""Authorize a prepared BSV input with an external one-time WOTS+ signer."""
from dataclasses import dataclass
from functools import cache

from script import COMPANION_CODE, ORDINARY_CODE, locking_script
from fixed_template import fixed_pattern
from shared.pushtx import N, R
from shared.script import number, push
from shared.transaction import (
    CHRONICLE, FORKID, SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_TYPES,
    Input, Transaction, amount, hash256, preimage_forkid, preimage_otda,
)
from wots import KEY_BYTES, verify_digest

DEFAULT_SIGHASH = FORKID | SIGHASH_ALL
COMPRESSIBLE_OTDA_TYPES = (0x61, 0xe1, 0x63, 0xe3)


@dataclass(frozen=True)
class SpendAuthorization:
    requested_type: int
    preimage: bytes
    companion: bool

    def digest(self):
        return hash256(self.preimage)


def authorization(tx, index, previous_amount, sighash=DEFAULT_SIGHASH):
    if type(sighash) is not int or sighash not in SIGHASH_TYPES or not 0 <= index < len(tx.inputs):
        raise ValueError('unsupported sighash or input index')
    amount(previous_amount)
    chronicle = bool(sighash & CHRONICLE)
    companion = chronicle and sighash & 31 == SIGHASH_SINGLE and index >= len(tx.outputs)
    if chronicle and not companion:
        preimage = preimage_otda(tx, index, ORDINARY_CODE, sighash)
    else:
        code = COMPANION_CODE if companion else ORDINARY_CODE
        preimage = preimage_forkid(tx, index, previous_amount, code, sighash & ~CHRONICLE)
    return SpendAuthorization(sighash, preimage, companion)


def _checked_digest(auth):
    digest = auth.digest()
    if (int.from_bytes(digest, 'big') + R) % N == 0:
        raise ValueError('degenerate binding digest; rebuild before signing')
    return digest


def current_input_unlock(auth, public_key, signature):
    if not verify_digest(public_key, _checked_digest(auth), signature):
        raise ValueError('invalid WOTS+ signature from external signer')
    return push(auth.preimage) + push(signature) + number(int(auth.companion))


@cache
def _layout_sizes():
    return {(transaction, profile): len(locking_script(bytes(KEY_BYTES), transaction=transaction,
                                                      cached_constants=profile))
            for transaction in (True, False) for profile in (False, True, 'steps')}


def _layouts_for_sizes(sizes):
    return (layout for layout, size in _layout_sizes().items() if size in sizes)


def sign_spend(tx, index, funding_raw, public_key, signer, *, sighash=DEFAULT_SIGHASH, compress_otda=False):
    """Check the input, call signer(digest32) once, and install its witness.

    The caller authenticates the funding transaction and approves the proposed
    transaction and sighash. The signer must persist key consumption before
    releasing a signature. A callback error may already have consumed the key.
    Enable compress_otda only for Chronicle functional unlocking.
    """
    if type(compress_otda) is not bool:
        raise ValueError('compress_otda must be a boolean')
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
    if not any(previous.script == locking_script(public_key, cached_constants=profile)
               for transaction, profile in _layouts_for_sizes({len(previous.script)}) if transaction):
        raise ValueError('funding output does not match public key and canonical template')
    # Filter expensive generation by the known layout lengths for each profile.
    sizes = {len(output.script) for output in tx.outputs}
    own_scripts = (locking_script(public_key, transaction=transaction, cached_constants=profile)
                   for transaction, profile in _layouts_for_sizes(sizes))
    if any(output.script == script for script in own_scripts for output in tx.outputs):
        raise ValueError('change must use a fresh WOTS+ key')
    auth = authorization(tx, index, previous.value, sighash)
    program = None
    if compress_otda and tx.version == 2 and not auth.companion and sighash in COMPRESSIBLE_OTDA_TYPES:
        outputs = (tx.outputs[index],) if sighash & 31 == SIGHASH_SINGLE else tx.outputs
        program = fixed_pattern().build(auth.preimage, outputs)
    signature = signer(_checked_digest(auth))
    witness = current_input_unlock(auth, public_key, signature)
    if program is not None:
        literal_size = len(push(auth.preimage))
        if len(program) < literal_size:
            witness = program + witness[literal_size:]
    return tx.with_script(index, witness)


def sign_payment(funding_raw, vout, outputs, fee, public_key, signer, *, sighash=DEFAULT_SIGHASH, compress_otda=False):
    """Construct a single-input spend whose outputs plus fee equal funding."""
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
    return sign_spend(tx, 0, funding_raw, public_key, signer, sighash=sighash, compress_otda=compress_otda)

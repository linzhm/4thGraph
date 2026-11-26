"""Transaction authorization using an external Lamport signer callback."""
from dataclasses import dataclass

from lamport import bits, verify_digest
from script import (
    COMPANION_CODE, ORDINARY_CODE, N, R, committed_locking_script, legacy_locking_script, locking_script,
)
from fourthgraph.bsv.script import number, push
from fourthgraph.bsv.transaction import (
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


def current_input_unlock(auth, public_key, signature, *, committed=False):
    if committed and auth.legacy:
        raise ValueError('the legacy lock does not use committed proofs')
    digest = _checked_digest(auth)
    if not verify_digest(public_key, digest, signature):
        raise ValueError('invalid Lamport signature from external signer')
    proof = signature
    if committed:
        items = []
        for index, choice in enumerate(bits(digest)):
            selected = 32 * index
            sibling = 64 * index + 32 * (1 - choice)
            items.extend((signature[selected:selected+32], public_key[sibling:sibling+32]))
        proof = b''.join(items)
    witness = push(auth.preimage) + push(proof)
    if auth.legacy:
        return witness
    return witness + number(int(auth.companion))


def sign_spend(tx, index, funding_raw, public_key, signer, *, sighash=DEFAULT_SIGHASH,
               allow_unpaired_single=False):
    """Authorize a prepared input. signer(digest32) returns a packed 8192-byte signature.

    The caller authenticates the funding outpoint and verifies the required
    confirmation depth before approving the transaction and requested mode.
    The external signer persists one-time key consumption before disclosure.
    The callback is invoked once after preflight. An unpaired SINGLE input
    commits to no outputs and requires allow_unpaired_single=True.
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
    return sign_previous(tx, index, funding.outputs[current.vout], public_key, signer,
                         sighash=sighash, allow_unpaired_single=allow_unpaired_single)


def sign_previous(tx, index, previous, public_key, signer, *, sighash=DEFAULT_SIGHASH, allow_unpaired_single=False):
    """Authorize an input with its already matched previous output."""
    universal = locking_script(public_key)
    legacy = legacy_locking_script(public_key)
    committed = committed_locking_script(public_key)
    if previous.script not in (universal, legacy, committed):
        raise ValueError('funding output does not match public key and canonical template')
    own_scripts = (universal, legacy, committed, locking_script(public_key, transaction=False))
    if any(output.script in own_scripts for output in tx.outputs):
        raise ValueError('change must use a fresh Lamport key')
    auth = authorization(tx, index, previous.value, sighash, legacy=previous.script == legacy)
    if (auth.requested_type & 31 == SIGHASH_SINGLE and index >= len(tx.outputs)
            and allow_unpaired_single is not True):
        raise ValueError('unpaired SINGLE commits to no outputs; explicit opt-in required')
    signature = signer(_checked_digest(auth))
    witness = current_input_unlock(auth, public_key, signature, committed=previous.script == committed)
    return tx.with_script(index, witness)


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

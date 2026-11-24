"""Create and recognize deferred P-256 payment outputs, and prepare activation inputs."""
from dataclasses import dataclass
from functools import cache
from hashlib import sha256
from pathlib import Path
import sys

from shared.script import OPS, assemble, push
from shared.transaction import (
    ANYONECANPAY, CHRONICLE, FORKID, SIGHASH_SINGLE, SIGHASH_TYPES,
    Output, Transaction, amount, hash256, preimage_forkid, preimage_otda,
)

R1_REFERENCE = Path(__file__).resolve().parents[2] / 'p2pkh-r1/reference'
sys.path.append(str(R1_REFERENCE))
from p2pkh_r1 import locking_script_from_owner_hash, public_key_hash160


PUBLIC_KEY_SIZE = 65
OWNER_HASH_SIZE = 20
SCRIPT_CODE = bytes([OPS['OP_CHECKSIG']])
COMPANION_CODE = bytes(OPS[name] for name in ('OP_CHECKSIGVERIFY', 'OP_ENDIF', 'OP_CODESEPARATOR', 'OP_CHECKSIG'))
ACTIVATION_SIGHASH = FORKID | SIGHASH_SINGLE
DIRECT_TYPES = (ACTIVATION_SIGHASH, ACTIVATION_SIGHASH | ANYONECANPAY)
ASM = Path(__file__).with_name('asm')


@dataclass(frozen=True)
class Commitment:
    owner_hash160: bytes
    script_hash: bytes
    output_hash: bytes
    public_key: bytes | None = None


def target_output(value: int, public_key: bytes) -> Output:
    """Return the canonical P2PKH-R1 destination at the full input value."""
    return target_output_from_owner_hash(value, public_key_hash160(public_key))


def target_output_from_owner_hash(value: int, owner_hash160: bytes) -> Output:
    amount(value)
    return Output(value, locking_script_from_owner_hash(owner_hash160))


@cache
def _binder_blocks() -> dict[str, bytes]:
    return {
        name: assemble(R1_REFERENCE / 'asm', bytes(20), entry=name)
        for name in ('UINT256BE', 'K1_BIND_DIGEST', 'CHECK_TYPE')
    }


def _locking_script(value: int, commitment: Commitment) -> bytes:
    return assemble(ASM, bytes(20), injected={
        **_binder_blocks(),
        'OWNER_IDENTIFIER': push(commitment.public_key or commitment.owner_hash160),
        'TARGET_SCRIPT_FINGERPRINT': push(commitment.script_hash),
        'VALUE': push(amount(value)),
        'TARGET_HASH': push(commitment.output_hash),
    })


def _commitment(owner_hash160: bytes, target: Output, public_key: bytes | None = None) -> Commitment:
    output_hash = hash256(target.serialize())
    if output_hash == bytes(32):
        raise ValueError('zero target commitment')
    return Commitment(owner_hash160, sha256(target.script).digest(), output_hash, public_key)


def funding_output(value: int, public_key: bytes) -> Output:
    """Construct a hash-only output from a validated uncompressed P-256 key."""
    return funding_output_from_owner_hash(value, public_key_hash160(public_key))


def funding_output_from_owner_hash(value: int, owner_hash160: bytes) -> Output:
    """Construct a short output from the same owner hash as ordinary P2PKH-R1."""
    commitment = _commitment(owner_hash160, target_output_from_owner_hash(value, owner_hash160))
    return Output(value, _locking_script(value, commitment))


def recognize(output: Output, *, expected_key: bytes | None = None,
              expected_owner_hash: bytes | None = None) -> Commitment | None:
    """Recognize only an exact canonical output, including both commitments and its value."""
    public_key = None
    try:
        if output.script.startswith(bytes([OWNER_HASH_SIZE])):
            owner = output.script[1:1 + OWNER_HASH_SIZE]
        elif output.script.startswith(bytes([PUBLIC_KEY_SIZE, 4])):
            public_key = output.script[1:1 + PUBLIC_KEY_SIZE]
            owner = public_key_hash160(public_key)
        else:
            return None
        if expected_owner_hash is not None and expected_owner_hash != owner:
            return None
        if expected_key is not None and public_key_hash160(expected_key) != owner:
            return None
        if expected_key is not None and public_key is not None and expected_key != public_key:
            return None
        target = target_output_from_owner_hash(output.value, owner)
        commitment = _commitment(owner, target, public_key)
    except ValueError:
        return None
    return commitment if output.script == _locking_script(output.value, commitment) else None


def activation_preimages(tx: Transaction, index: int, value: int, sighash: int) -> tuple[bytes, bytes]:
    """Return the ForkID output check preimage and optional selected-digest witness."""
    if sighash not in SIGHASH_TYPES:
        raise ValueError('unsupported activation sighash type')
    if not 0 <= index < len(tx.inputs) or index >= len(tx.outputs):
        raise ValueError('activation needs a same-index output')
    if sighash in DIRECT_TYPES:
        return preimage_forkid(tx, index, value, SCRIPT_CODE, sighash), b''
    if sighash & CHRONICLE:
        selected = preimage_otda(tx, index, SCRIPT_CODE, sighash)
    else:
        selected = preimage_forkid(tx, index, value, SCRIPT_CODE, sighash)
    bound_type = ACTIVATION_SIGHASH | (sighash & ANYONECANPAY)
    bound = preimage_forkid(tx, index, value, COMPANION_CODE, bound_type)
    return bound, bytes([sighash]) + hash256(selected)


def activate_input(tx: Transaction, index: int, funding_raw: bytes, *,
                   sighash: int = ACTIVATION_SIGHASH) -> Transaction:
    """Prepare one activation input in an already assembled transaction, without a private key."""
    if not 0 <= index < len(tx.inputs) or index >= len(tx.outputs):
        raise ValueError('activation needs a same-index output')
    current = tx.inputs[index]
    if current.script:
        raise ValueError('activation input already has an unlocking script')
    funding = Transaction.parse(funding_raw)
    if current.txid != funding.txid_wire() or not 0 <= current.vout < len(funding.outputs):
        raise ValueError('funding outpoint mismatch')
    previous = funding.outputs[current.vout]
    commitment = recognize(previous)
    if commitment is None:
        raise ValueError('funding output is not a canonical deferred lock')
    if hash256(tx.outputs[index].serialize()) != commitment.output_hash:
        raise ValueError('activation output does not match the committed value and R1 script')
    preimage, additional = activation_preimages(tx, index, previous.value, sighash)
    unlock = (push(additional) if additional else b'') + push(preimage)
    return tx.with_script(index, unlock)

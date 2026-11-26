"""Create and recognize deferred P-256 payment outputs, and prepare activation inputs."""
from dataclasses import dataclass, replace
from functools import cache
from hashlib import sha256
from pathlib import Path
import sys

from fourthgraph.bsv.script import OPS, assemble, push
from fourthgraph.bsv.transaction import (
    ANYONECANPAY, CHRONICLE, FORKID, SIGHASH_SINGLE, SIGHASH_TYPES,
    Output, Transaction, amount, hash256, preimage_forkid, preimage_otda,
)
from fourthgraph.compiler.lowering import OPTIMIZATIONS

from forth_lock import DEFERRED_TEMPLATE_VERSION, RELEASE_OPTIMIZATION, compile_template, released_template

R1_REFERENCE = Path(__file__).resolve().parents[2] / 'p2pkh-r1/reference'
sys.path.append(str(R1_REFERENCE))
from fixed_templates import LEGACY_TEMPLATE_VERSION, TEMPLATE_VERSIONS
from p2pkh_r1 import locking_script_from_owner_hash, public_key_hash160


PUBLIC_KEY_SIZE = 65
OWNER_HASH_SIZE = 20
SCRIPT_CODE = bytes([OPS['OP_CHECKSIG']])
COMPANION_CODE = bytes(OPS[name] for name in ('OP_CHECKSIGVERIFY', 'OP_ENDIF', 'OP_CODESEPARATOR', 'OP_CHECKSIG'))
ACTIVATION_SIGHASH = FORKID | SIGHASH_SINGLE
DIRECT_TYPES = (ACTIVATION_SIGHASH, ACTIVATION_SIGHASH | ANYONECANPAY)
ASM = Path(__file__).with_name('asm')
TARGET_R1_VERSION = "0.2.0"
ASSEMBLY_TEMPLATE_VERSION = "0.2.0"
RELEASE_BUILD = "release"


@dataclass(frozen=True)
class Commitment:
    owner_hash160: bytes
    script_hash: bytes
    output_hash: bytes
    target_r1_version: str
    public_key: bytes | None = None
    optimization: str | None = None
    template_version: str | None = None


def target_output(value: int, public_key: bytes, *, target_r1_version: str = TARGET_R1_VERSION) -> Output:
    """Return the versioned P2PKH-R1 destination at the full input value."""
    return target_output_from_owner_hash(value, public_key_hash160(public_key),
                                         target_r1_version=target_r1_version)


def target_output_from_owner_hash(value: int, owner_hash160: bytes, *,
                                  target_r1_version: str = TARGET_R1_VERSION) -> Output:
    amount(value)
    return Output(value, locking_script_from_owner_hash(owner_hash160, template_version=target_r1_version))


@cache
def _binder_blocks() -> dict[str, bytes]:
    return {
        name: assemble(R1_REFERENCE / 'asm', bytes(20), entry=name)
        for name in ('UINT256BE', 'K1_BIND_DIGEST', 'CHECK_TYPE')
    }


def _locking_script(value: int, commitment: Commitment, optimization: str | None) -> bytes:
    owner = commitment.public_key or commitment.owner_hash160
    if optimization is not None:
        template = released_template() if optimization == RELEASE_BUILD else compile_template(optimization)
        return template.bind(owner, commitment.script_hash, amount(value), commitment.output_hash)
    return assemble(ASM, bytes(20), injected={
        **_binder_blocks(),
        'HEADER': push(owner) + push(commitment.script_hash),
        'VALUE': push(amount(value)),
        'TARGET_HASH': push(commitment.output_hash),
    })


def _commitment(owner_hash160: bytes, target: Output, target_r1_version: str,
                public_key: bytes | None = None) -> Commitment:
    output_hash = hash256(target.serialize())
    if output_hash == bytes(32):
        raise ValueError('zero target commitment')
    return Commitment(owner_hash160, sha256(target.script).digest(), output_hash, target_r1_version, public_key)


def funding_output(value: int, public_key: bytes, *, target_r1_version: str = TARGET_R1_VERSION,
                   optimization: str | None = RELEASE_BUILD) -> Output:
    """Construct a hash-only output from a validated uncompressed P-256 key."""
    return funding_output_from_owner_hash(value, public_key_hash160(public_key),
                                          target_r1_version=target_r1_version, optimization=optimization)


def funding_output_from_owner_hash(value: int, owner_hash160: bytes, *,
                                   target_r1_version: str = TARGET_R1_VERSION,
                                   optimization: str | None = RELEASE_BUILD) -> Output:
    """Construct a short output from the same owner hash as ordinary P2PKH-R1."""
    target = target_output_from_owner_hash(value, owner_hash160, target_r1_version=target_r1_version)
    commitment = _commitment(owner_hash160, target, target_r1_version)
    return Output(value, _locking_script(value, commitment, optimization))


def recognize(output: Output, *, expected_key: bytes | None = None,
              expected_owner_hash: bytes | None = None) -> Commitment | None:
    """Recognize only an exact canonical output, including both commitments and its value."""
    script = output.script
    if script.startswith(bytes([OWNER_HASH_SIZE])):
        recipient_end = 1 + OWNER_HASH_SIZE
    elif script.startswith(bytes([PUBLIC_KEY_SIZE, 4])):
        recipient_end = 1 + PUBLIC_KEY_SIZE
    else:
        return None
    hash_end = recipient_end + 33  # Direct push of the 32-byte script hash.
    if (len(script) <= hash_end + 1 or script[recipient_end] != 32
            or script[hash_end] != OPS['OP_2DROP']):
        return None

    public_key = None
    owner = script[1:recipient_end]
    try:
        if recipient_end == 1 + PUBLIC_KEY_SIZE:
            public_key = owner
            owner = public_key_hash160(public_key)
        if expected_owner_hash is not None and expected_owner_hash != owner:
            return None
        if expected_key is not None and public_key_hash160(expected_key) != owner:
            return None
        if expected_key is not None and public_key is not None and expected_key != public_key:
            return None
        commitments = tuple(
            _commitment(owner, target_output_from_owner_hash(output.value, owner, target_r1_version=version),
                        version, public_key)
            for version in TEMPLATE_VERSIONS
        )
        for build in (None, RELEASE_BUILD, *OPTIMIZATIONS):
            for commitment in commitments:
                if script != _locking_script(output.value, commitment, build):
                    continue
                if build == RELEASE_BUILD:
                    return replace(commitment, optimization=RELEASE_OPTIMIZATION,
                                   template_version=DEFERRED_TEMPLATE_VERSION)
                if build is None:
                    legacy = public_key is not None or commitment.target_r1_version == LEGACY_TEMPLATE_VERSION
                    return replace(commitment,
                                   template_version=LEGACY_TEMPLATE_VERSION if legacy else ASSEMBLY_TEMPLATE_VERSION)
                return replace(commitment, optimization=build)
    except ValueError:
        return None
    return None


def activation_preimages(tx: Transaction, index: int, value: int, sighash: int) -> tuple[bytes, bytes]:
    """Return the BIP143 output check preimage and optional selected-digest witness."""
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
    return activate_previous(tx, index, funding.outputs[current.vout], sighash=sighash)


def activate_previous(tx: Transaction, index: int, previous: Output, *,
                      sighash: int = ACTIVATION_SIGHASH) -> Transaction:
    """Prepare activation with an already matched previous output."""
    if index >= len(tx.outputs):
        raise ValueError('activation needs a same-index output')
    commitment = recognize(previous)
    if commitment is None:
        raise ValueError('funding output is not a canonical deferred lock')
    if hash256(tx.outputs[index].serialize()) != commitment.output_hash:
        raise ValueError('activation output does not match the committed value and R1 script')
    preimage, additional = activation_preimages(tx, index, previous.value, sighash)
    unlock = (push(additional) if additional else b'') + push(preimage)
    return tx.with_script(index, unlock)

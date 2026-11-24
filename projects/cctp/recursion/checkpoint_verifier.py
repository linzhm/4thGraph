"""Verify one fixed parent-checkpoint proof against a real BSV outpoint.

The proof authenticates the hidden prefix, midstate and disclosed suffix.
Script binds its public statement to the actual parent and checks the selected
output. This is an isolated fixed-layout probe, not a general parent parser.
"""

from mimo_verifier import _split, _unsigned
from shared.script import asm, number, push
from shared.transaction import Output, blob, hash256, preimage_all
from statement import fixed, uint
from transfer import (COMPACT_SCRIPTCODE, COMPACT_SUFFIX, compact_preimage_digest_script,
                      compact_verifier_binding, digest_limbs_script)
from verifier import locking_script


DOMAIN = b"BSV/CCTP/parent-checkpoint/v1\x00"
PARENT_BYTES = 332
PROCESSED_BYTES = 256
SUFFIX_BYTES = PARENT_BYTES - PROCESSED_BYTES
OUTPUT_COUNT_OFFSET = 307
OUTPUT_COUNT = 2
OUTPUT_COUNT_IN_SUFFIX = OUTPUT_COUNT_OFFSET - PROCESSED_BYTES
OUTPUTS_IN_SUFFIX = OUTPUT_COUNT_IN_SUFFIX + 1
OUTPUT_BYTES = 10
OUTPUTS_BYTES = OUTPUT_COUNT * OUTPUT_BYTES
PROFILE = uint(PROCESSED_BYTES, 8) + uint(OUTPUT_COUNT_OFFSET, 4) + uint(OUTPUT_COUNT, 4)


def _outputs(suffix):
    fixed(suffix, SUFFIX_BYTES)
    if (suffix[OUTPUT_COUNT_IN_SUFFIX] != OUTPUT_COUNT
            or any(suffix[OUTPUTS_IN_SUFFIX + index * OUTPUT_BYTES + 8] != 1 for index in range(OUTPUT_COUNT))):
        raise ValueError("expected checkpoint suffix with exactly two canonical one-byte-lock TxOuts")
    return suffix[OUTPUTS_IN_SUFFIX:OUTPUTS_IN_SUFFIX + OUTPUTS_BYTES]


def statement_bytes(parent_txid_wire, state, suffix):
    """Derive the exact proof public message without authenticating the checkpoint."""
    outputs = _outputs(suffix)
    return (DOMAIN + fixed(parent_txid_wire, 32) + fixed(state, 32) + PROFILE
            + hash256(suffix) + hash256(outputs))


def _slice(offset, length):
    return _split(offset) + asm("OP_NIP") + _split(length) + asm("OP_DROP")


def _size(size):
    return asm("OP_SIZE") + number(size) + asm("OP_NUMEQUALVERIFY")


def _suffix_shape():
    layout = ((OUTPUT_COUNT_IN_SUFFIX, OUTPUT_COUNT),
              *((OUTPUTS_IN_SUFFIX + i * OUTPUT_BYTES + 8, 1) for i in range(OUTPUT_COUNT)))
    return _size(SUFFIX_BYTES) + b"".join(
        asm("OP_DUP") + _slice(offset, 1) + push(bytes([value])) + asm("OP_EQUALVERIFY")
        for offset, value in layout
    ) + asm("OP_DROP")


def _selected_output(required_output):
    if required_output is None:
        return asm("OP_DROP")
    if not isinstance(required_output, Output) or len(required_output.script) != 1:
        raise ValueError("checkpoint profile selects a canonical one-byte locking script")
    return (
        asm("OP_2 OP_PICK") + _slice(OUTPUTS_IN_SUFFIX, OUTPUTS_BYTES) + asm("OP_SWAP OP_IF")
        + _split(OUTPUT_BYTES) + asm("OP_NIP OP_ELSE") + _split(OUTPUT_BYTES) + asm("OP_DROP OP_ENDIF")
        + push(required_output.serialize()) + asm("OP_EQUALVERIFY")
    )


def statement_script(*, required_output=None):
    """Consume [state, suffix, prevouts, compact preimage], leaving the proof's two public limbs."""
    script_field = blob(COMPACT_SCRIPTCODE)
    return (
        asm("OP_3 OP_PICK") + _size(32) + asm("OP_DROP OP_2 OP_PICK") + _suffix_shape()
        # Bind this exact compact preimage with the final native CHECKSIG after the proof check.
        + asm("OP_DUP") + compact_preimage_digest_script() + asm("OP_DROP OP_DUP")
        + _slice(104, len(script_field)) + push(script_field) + asm("OP_EQUALVERIFY")
        + asm("OP_OVER") + _size(72) + asm("OP_HASH256 OP_OVER") + _slice(4, 32) + asm("OP_EQUALVERIFY")
        + asm("OP_OVER 36 OP_SPLIT OP_NIP OP_OVER") + _slice(68, 36) + asm("OP_EQUALVERIFY OP_DROP")
        # The actual vin0 prevout contributes its txid to the proof and selects a disclosed TxOut.
        + _split(36) + asm("OP_DROP") + _split(32) + _unsigned()
        + asm("OP_DUP OP_2 OP_LESSTHAN OP_VERIFY") + _selected_output(required_output)
        # [state, suffix, actual parent txid] becomes the exact proof public message.
        + asm("OP_OVER OP_HASH256 OP_TOALTSTACK OP_OVER") + _slice(OUTPUTS_IN_SUFFIX, OUTPUTS_BYTES)
        + asm("OP_HASH256 OP_TOALTSTACK OP_ROT OP_CAT OP_NIP") + push(PROFILE)
        + asm("OP_CAT OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_CAT OP_CAT") + push(DOMAIN)
        + asm("OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script()
    )


def verifier_lock(key, *, required_output=None):
    if len(key.ic) != 3:
        raise ValueError("the checkpoint profile requires a plain Groth16 key with two public limbs")
    proof_lock = locking_script(key, None, projective_g1=True, projective_g2=True, reuse_constants=True)[0]
    return statement_script(required_output=required_output) + proof_lock + compact_verifier_binding()


def verifier_material(tx, funding, state, suffix):
    """Build the checkpoint witness after proof fields for the actual verifier at vin1."""
    fixed(state, 32)
    _outputs(suffix)
    if len(tx.inputs) != 2:
        raise ValueError("expected the parent at vin0 and its checkpoint verifier at vin1")
    current = tx.inputs[1]
    if current.txid != funding.txid_wire() or not 0 <= current.vout < len(funding.outputs):
        raise ValueError("checkpoint verifier funding is not the actual vin1 outpoint")
    previous = funding.outputs[current.vout]
    if not previous.script.endswith(COMPACT_SUFFIX):
        raise ValueError("expected a compact binding suffix in the checkpoint verifier lock")
    preimage = preimage_all(tx, 1, previous.value, COMPACT_SCRIPTCODE)
    prevouts = b"".join(item.outpoint() for item in tx.inputs)
    return b"".join(map(push, (state, suffix, prevouts, preimage)))

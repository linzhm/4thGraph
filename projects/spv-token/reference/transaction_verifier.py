"""Bind the experimental CCTP proof to the verifier input's spending transaction."""

from descriptor import VerifierDescriptor
from public_inputs import verification_key_point
from shared.script import asm, push
from shared.transaction import hash256, preimage_all
from statement import TRANSFER_DOMAIN, public_inputs, transfer_bytes
from transfer import (
    COMPACT_SCRIPTCODE,
    compact_preimage_digest_script,
    compact_verifier_binding,
    digest_limbs_script,
)
from verifier import locking_script, unlocking_fields, unlocking_script


def verifier_key_id(key):
    return hash256(VerifierDescriptor(key, (0, 0)).encode())


def verifier_lock(asset, key):
    body, _, _ = locking_script(
        key, None, projective_g1=True, projective_g2=True, reuse_constants=True,
    )
    identity = TRANSFER_DOMAIN + asset.asset_id() + verifier_key_id(key)
    return (
        compact_preimage_digest_script()
        + push(identity)
        + asm("OP_SWAP OP_CAT OP_SWAP OP_CAT OP_HASH256")
        + digest_limbs_script()
        + body
        + compact_verifier_binding()
    )


def verifier_witness(asset, key, proof, tx, parent, inputs, outputs):
    lock = verifier_lock(asset, key)
    statement = transfer_bytes(
        asset, verifier_key_id(key), tx, parent, lock, inputs, outputs,
        script_code=COMPACT_SCRIPTCODE,
    )
    signals = public_inputs(statement)
    point = verification_key_point(key.ic, signals) or (0, 0)
    fields = unlocking_fields(key, signals, proof, projective_g1=True, projective_g2=True)
    previous_output = parent.outputs[tx.inputs[0].vout]
    preimage = preimage_all(tx, 0, previous_output.value, COMPACT_SCRIPTCODE)
    slot_offset = len(TRANSFER_DOMAIN) + 96
    return unlocking_script((*point, *fields)) + push(statement[slot_offset:]) + push(preimage)

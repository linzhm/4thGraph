"""Adapt authenticated ALL contexts to the existing narrow transaction relation."""
from chronicle_preimage import CHRONICLE_ALL, LEGACY_ALL, VERIFIER_SEQUENCES
from chronicle_preimage_script import otda_all_fields
from continuity_preimage import CURRENT_AMOUNT, _funding_field
from mimo_verifier import _pick, _split
from shared.pushtx import binding_der
from shared.script import asm, push
from shared.transaction import blob
from transfer import COMPACT_SCRIPTCODE, COMPACT_SUFFIX, compact_preimage_digest_script


def _check_sequence(sighash):
    expected = VERIFIER_SEQUENCES[sighash].to_bytes(4, "little")
    return (
        asm("OP_DUP") + _split(CURRENT_AMOUNT + 8) + asm("OP_NIP OP_4 OP_SPLIT OP_DROP")
        + push(expected) + asm("OP_EQUALVERIFY")
    )


def _otda_relation_material(input_count, output_count, verifier_index, ancestors):
    # Above the funding and ancestor material, the parser leaves version,
    # outpoints, sequences, verifier outpoint and sequence, outputs, locktime.
    return (
        asm("OP_DUP OP_HASH256 OP_TOALTSTACK") + otda_all_fields(input_count, output_count, verifier_index)
        + _pick(7 + ancestors) + _pick(4) + _funding_field() + asm("OP_DROP")
        # Build the field layout used by the common covenant. The actual
        # signature and the continuity statement use the original OTDA digest.
        + asm("OP_SWAP OP_TOALTSTACK OP_SWAP OP_DUP OP_TOALTSTACK OP_HASH256 OP_TOALTSTACK")
        + asm("OP_SWAP OP_CAT OP_SWAP") + push(blob(COMPACT_SCRIPTCODE)) + asm("OP_CAT OP_SWAP OP_CAT")
        + asm("OP_SWAP OP_HASH256 OP_SWAP OP_CAT OP_OVER OP_TOALTSTACK OP_SWAP OP_HASH256 OP_SWAP OP_CAT OP_CAT")
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_ROT OP_SWAP OP_CAT OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK OP_CAT")
        + push(bytes([LEGACY_ALL, 0, 0, 0])) + asm("OP_CAT OP_ROT OP_SWAP")
    )


def all_relation_material(input_count, output_count, verifier_index, ancestors):
    """Adapt one of the two ALL witnesses and save its actual digest."""
    return (
        asm("OP_DUP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP OP_1 OP_SPLIT") + push(bytes(3))
        + asm("OP_EQUALVERIFY OP_DUP OP_TOALTSTACK") + push(bytes([CHRONICLE_ALL])) + asm("OP_EQUAL OP_IF")
        + _otda_relation_material(input_count, output_count, verifier_index, ancestors)
        + _check_sequence(CHRONICLE_ALL) + asm("OP_ELSE OP_DUP") + compact_preimage_digest_script()
        + asm("OP_DROP") + _check_sequence(LEGACY_ALL) + asm("OP_ENDIF")
    )


def use_actual_context_digest():
    """Replace the relation's preimage with the digest saved at entry."""
    return asm("OP_DROP OP_FROMALTSTACK OP_DUP OP_TOALTSTACK")


def bind_all_context():
    """Require the proof result and authenticate the actual digest and signature type."""
    return asm("OP_VERIFY OP_FROMALTSTACK") + binding_der() + asm("OP_FROMALTSTACK OP_CAT") + COMPACT_SUFFIX

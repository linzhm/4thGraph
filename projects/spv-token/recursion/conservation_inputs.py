"""Bind both conservation proof slots to the actual expected token locks."""

from conservation_probe import METADATA_PREFIX, METADATA_SIZE, token_statement_script
from continuity_preimage import _funding_output
from mimo_verifier import _match_prefix, _select_parent_output, _split, _unsigned
from shared.script import asm, push


def _slice(offset, length):
    return _split(offset) + asm("OP_NIP") + _split(length) + asm("OP_DROP")


def _same_token_lock():
    """Consume [expected body, parent raw, actual outpoint] and retain the body."""
    return (
        _split(32) + asm("OP_TOALTSTACK OP_OVER OP_HASH256 OP_EQUALVERIFY OP_FROMALTSTACK")
        + _unsigned() + _select_parent_output() + _match_prefix(METADATA_PREFIX)
        + _split(METADATA_SIZE) + asm("OP_NIP OP_OVER OP_EQUALVERIFY")
    )


def actual_token_inputs_script():
    """Consume direct-parent and companion bytes before the generic proof verifier.

    Input suffix is [token parent0, token parent1 or empty, companion funding,
    outputs, prevouts, compact preimage]. The final three items are retained.
    The receipt verifier then authenticates the same serialized prevouts.
    """
    marker = bytes(range(32))
    template = asm("OP_2DROP") + token_statement_script(marker)
    lead, tail = template.split(marker)
    expected = push(lead) + asm("OP_SWAP OP_CAT") + push(tail) + asm("OP_CAT")
    shape = asm("OP_3 OP_ROLL OP_2 OP_PICK") + _slice(36, 36) + _funding_output() + asm("OP_NIP")
    return (
        shape + expected
        + asm("OP_5 OP_PICK OP_3 OP_PICK") + _slice(72, 36) + _same_token_lock()
        + asm("OP_4 OP_PICK OP_SIZE OP_0 OP_NUMEQUAL OP_IF OP_DROP OP_5 OP_PICK OP_ENDIF OP_3 OP_PICK")
        + _slice(108, 36) + _same_token_lock()
        + asm("OP_DROP OP_4 OP_ROLL OP_DROP OP_3 OP_ROLL OP_DROP")
    )


def actual_token_inputs_material(parents, companion):
    left, right = (tx for tx, _ in parents)
    left_raw, right_raw = left.serialize(), right.serialize()
    return push(left_raw) + push(b"" if left_raw == right_raw else right_raw) + push(companion.serialize())

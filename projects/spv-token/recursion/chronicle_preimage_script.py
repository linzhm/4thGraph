"""Structural parsing for a shared verifier's canonical Chronicle OTDA ALL preimage."""

from mimo_verifier import _match_prefix, _pick, _split
from parent_preimage import _skip_output
from shared.script import asm, push
from shared.transaction import CHRONICLE, FORKID, SIGHASH_ALL, blob, compact
from transfer import COMPACT_SCRIPTCODE

MAX_INPUTS = 258
MAX_OUTPUTS = 257
OUTPOINT_BYTES = 36
SEQUENCE_BYTES = 4
EMPTY_INPUT_BYTES = OUTPOINT_BYTES + len(blob(b"")) + SEQUENCE_BYTES
SIGHASH_WORD = (FORKID | CHRONICLE | SIGHASH_ALL).to_bytes(4, "little")
REQUIRE_EMPTY = asm("OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP")


def _input_fields(script_field):
    """Consume the next input, appending its outpoint and sequence to their columns."""
    return (
        _split(OUTPOINT_BYTES) + _match_prefix(script_field) + _split(SEQUENCE_BYTES)
        + asm("OP_TOALTSTACK OP_ROT OP_SWAP OP_CAT OP_TOALTSTACK OP_CAT OP_FROMALTSTACK OP_FROMALTSTACK")
    )


def _selected_field(column_depth, index, width):
    offset = _split(index * width) + asm("OP_NIP") if index else b""
    return _pick(column_depth) + offset + _split(width) + asm("OP_DROP")


def otda_all_fields(input_count, output_count, verifier_index, *, script_code=COMPACT_SCRIPTCODE):
    """Consume raw 0x61 preimage and preserve underlying stack and altstack.

    Leave [version, prevouts, sequences, current_outpoint, current_sequence,
    outputs, locktime]. The concatenated columns and output fields exclude
    their count prefixes. The enclosing lock authenticates the same raw
    preimage through the actual executing input's Chronicle signature.
    """
    if type(input_count) is not int or not 1 <= input_count <= MAX_INPUTS:
        raise ValueError("OTDA input count outside the bounded profile")
    if type(output_count) is not int or not 1 <= output_count <= MAX_OUTPUTS:
        raise ValueError("OTDA output count outside the bounded profile")
    if type(verifier_index) is not int or not 0 <= verifier_index < input_count:
        raise ValueError("OTDA verifier index outside the input profile")
    if type(script_code) is not bytes or not 1 <= len(script_code) <= 0xffffffff:
        raise ValueError("expected an explicit nonempty OTDA scriptCode")

    empty_script_field = blob(b"")
    verifier_script_field = blob(script_code)
    input_bytes = EMPTY_INPUT_BYTES * input_count + len(verifier_script_field) - len(empty_script_field)
    parse_empty = _input_fields(empty_script_field)
    return (
        _split(4) + _match_prefix(compact(input_count)) + _split(input_bytes)
        + asm("OP_TOALTSTACK OP_0 OP_0 OP_ROT")
        + parse_empty * verifier_index + _input_fields(verifier_script_field)
        + parse_empty * (input_count - verifier_index - 1)
        + REQUIRE_EMPTY + asm("OP_FROMALTSTACK")
        + _match_prefix(compact(output_count)) + asm("OP_SIZE OP_8 OP_SUB OP_SPLIT")
        + _split(4) + push(SIGHASH_WORD) + asm("OP_EQUALVERIFY OP_TOALTSTACK")
        + asm("OP_DUP") + _skip_output() * output_count + REQUIRE_EMPTY
        + _selected_field(2, verifier_index, OUTPOINT_BYTES)
        + _selected_field(2, verifier_index, SEQUENCE_BYTES)
        + asm("OP_ROT OP_FROMALTSTACK")
    )

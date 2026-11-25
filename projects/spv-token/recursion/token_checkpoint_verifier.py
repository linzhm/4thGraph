"""Compare checkpoint and full-parent binding for one native token rollover."""

from checkpoint_verifier import DOMAIN, _size, _slice
from operational_token import FLAG_OFFSET, METADATA_SIZE, TOKEN_MARKER
from shared.script import asm, push
from shared.transaction import blob, compact, hash256, preimage_all
from statement import fixed, uint
from transfer import (COMPACT_SCRIPTCODE, COMPACT_SUFFIX, compact_preimage_digest_script,
                      compact_verifier_binding, digest_limbs_script)
from verifier import locking_script


PARENT_BYTES = 3433
PROCESSED_BYTES = 1856
SUFFIX_BYTES = PARENT_BYTES - PROCESSED_BYTES
OUTPUT_COUNT_OFFSET = 1871
OUTPUT_START = OUTPUT_COUNT_OFFSET + 1
OUTPUT_END = PARENT_BYTES - 4
OUTPUT_SIZE = OUTPUT_END - OUTPUT_START
TOKEN_LOCK_BYTES = 1546
NATIVE_WITNESS_BYTES = 1782
SUFFIX_OUTPUT_START = OUTPUT_START - PROCESSED_BYTES
PROFILE = uint(PROCESSED_BYTES, 8) + uint(OUTPUT_COUNT_OFFSET, 4) + uint(1, 4)
OUTPUT_SCRIPT_START = 8 + len(compact(TOKEN_LOCK_BYTES))
TOKEN_PREFIX = TOKEN_MARKER + bytes([METADATA_SIZE])
TOKEN_OUTPUT_FLAG = OUTPUT_SCRIPT_START + FLAG_OFFSET


def _disclosed_output(suffix):
    fixed(suffix, SUFFIX_BYTES)
    if suffix[SUFFIX_OUTPUT_START - 1] != 1 or suffix[10] != 0:
        raise ValueError("expected one output and an empty sponsor witness in the token checkpoint")
    output = suffix[SUFFIX_OUTPUT_START:SUFFIX_OUTPUT_START + OUTPUT_SIZE]
    if (output[8:OUTPUT_SCRIPT_START] != compact(TOKEN_LOCK_BYTES)
            or not output[OUTPUT_SCRIPT_START:].startswith(TOKEN_PREFIX) or output[TOKEN_OUTPUT_FLAG] != 0):
        raise ValueError("expected the profiled active native token TxOut")
    return output


def statement_bytes(parent_txid_wire, state, suffix):
    """Construct the fixed public message. Only the proof authenticates the checkpoint."""
    _disclosed_output(suffix)
    return DOMAIN + fixed(parent_txid_wire, 32) + fixed(state, 32) + PROFILE + hash256(suffix) + bytes(32)


def _output_field():
    """Consume the exact disclosed suffix and return its sole active token TxOut."""
    return (
        _size(SUFFIX_BYTES)
        + asm("OP_DUP") + _slice(10, 1) + push(b"\x00") + asm("OP_EQUALVERIFY OP_DUP")
        + _slice(SUFFIX_OUTPUT_START - 1, 1) + push(b"\x01") + asm("OP_EQUALVERIFY")
        + _slice(SUFFIX_OUTPUT_START, OUTPUT_SIZE)
        + asm("OP_DUP") + _slice(8, OUTPUT_SCRIPT_START - 8) + push(compact(TOKEN_LOCK_BYTES))
        + asm("OP_EQUALVERIFY OP_DUP") + _slice(OUTPUT_SCRIPT_START, len(TOKEN_PREFIX)) + push(TOKEN_PREFIX)
        + asm("OP_EQUALVERIFY OP_DUP") + _slice(TOKEN_OUTPUT_FLAG, 1) + push(b"\x00") + asm("OP_EQUALVERIFY")
    )


def _bind_current():
    """Consume [prevouts, preimage], keeping actual token txid and hashOutputs; defer native CHECKSIG."""
    script_field = blob(COMPACT_SCRIPTCODE)
    return (
        asm("OP_DUP") + compact_preimage_digest_script() + asm("OP_DROP OP_DUP")
        + _slice(104, len(script_field)) + push(script_field) + asm("OP_EQUALVERIFY")
        + asm("OP_OVER") + _size(72) + asm("OP_HASH256 OP_OVER") + _slice(4, 32) + asm("OP_EQUALVERIFY")
        + asm("OP_OVER 36 OP_SPLIT OP_DROP OP_OVER") + _slice(68, 36) + asm("OP_EQUALVERIFY")
        + asm("OP_OVER 36 OP_SPLIT OP_NIP 32 OP_SPLIT") + push(bytes(4)) + asm("OP_EQUALVERIFY OP_SWAP")
        + _slice(152, 32) + asm("OP_ROT OP_DROP")
    )


def statement_script():
    """Consume [state, suffix, prevouts, compact preimage] and expose both proof limbs."""
    return (
        _bind_current() + asm("OP_2 OP_PICK") + _output_field() + asm("OP_HASH256 OP_EQUALVERIFY")
        + asm("OP_2 OP_PICK") + _size(32) + asm("OP_DROP OP_OVER OP_HASH256 OP_TOALTSTACK OP_ROT OP_CAT OP_NIP")
        + push(PROFILE) + asm("OP_CAT OP_FROMALTSTACK OP_CAT") + push(bytes(32)) + asm("OP_CAT")
        + push(DOMAIN) + asm("OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script()
    )


def verifier_lock(key):
    """Build the plain-checkpoint verifier for actual vin0."""
    if len(key.ic) != 3:
        raise ValueError("expected a plain Groth16 key for the two checkpoint limbs")
    proof_lock = locking_script(key, None, projective_g1=True, projective_g2=True, reuse_constants=True)[0]
    return statement_script() + proof_lock + compact_verifier_binding()


def raw_verifier_lock():
    """Authenticate the same parent and rollover directly from the full native transaction."""
    return (
        _bind_current() + asm("OP_2 OP_PICK OP_HASH256 OP_2 OP_PICK OP_EQUALVERIFY OP_NIP OP_SWAP")
        + _size(PARENT_BYTES) + asm("OP_DUP") + _slice(4, 1) + push(b"\x02") + asm("OP_EQUALVERIFY OP_DUP")
        + _slice(41, 3) + push(compact(NATIVE_WITNESS_BYTES)) + asm("OP_EQUALVERIFY")
        + _slice(PROCESSED_BYTES, SUFFIX_BYTES) + _output_field() + asm("OP_HASH256 OP_EQUALVERIFY OP_1")
        + compact_verifier_binding()
    )


def _current_material(tx, funding):
    if len(tx.inputs) != 2:
        raise ValueError("expected verifier vin0 and native token vin1")
    current = tx.inputs[0]
    if current.txid != funding.txid_wire() or not 0 <= current.vout < len(funding.outputs):
        raise ValueError("funding is not the actual verifier at vin0")
    previous = funding.outputs[current.vout]
    if not previous.script.endswith(COMPACT_SUFFIX):
        raise ValueError("expected the compact ForkID binding suffix")
    return b"".join(txin.outpoint() for txin in tx.inputs), preimage_all(tx, 0, previous.value, COMPACT_SCRIPTCODE)


def verifier_material(tx, funding, state, suffix):
    """Build the transaction witness suffix for the proof-bearing variant."""
    fixed(state, 32)
    _disclosed_output(suffix)
    return b"".join(map(push, (state, suffix, *_current_material(tx, funding))))


def raw_verifier_material(tx, funding, raw):
    """Build the corresponding witness for the native full-parent baseline."""
    fixed(raw, PARENT_BYTES)
    return b"".join(map(push, (raw, *_current_material(tx, funding))))

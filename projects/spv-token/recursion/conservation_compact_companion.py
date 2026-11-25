"""Reconstruct actual conservation parents in the already-required companion input."""

from hashlib import sha256

from capacity_records import capacity_record_script, encode_capacity_record
from conservation_inputs import _same_token_lock, _slice
from conservation_probe import token_statement_script
from continuity_preimage import _funding_field
from shared.script import asm, number, push
from shared.transaction import blob, preimage_all
from transfer import authenticate_forkid_preimage


MAX_PARENT_BYTES = 8_000_000


def _size_limit():
    return asm("OP_SIZE") + number(MAX_PARENT_BYTES) + asm("OP_LESSTHANOREQUAL OP_VERIFY")


def _parent_record():
    """Decode [record, verifier script field, companion script field]."""
    return (
        asm("OP_ROT") + _size_limit() + asm("OP_ROT OP_ROT")
        + capacity_record_script() + _size_limit()
    )


def companion_lock(verifier_lock):
    """Pin the actual vin0 verifier and authenticate both actual token parents at vin1."""
    if type(verifier_lock) is not bytes or not verifier_lock:
        raise ValueError("expected the complete verifier lock")
    marker = bytes(range(32))
    template = asm("OP_2DROP") + token_statement_script(marker)
    lead, tail = template.split(marker)
    expected_body = push(lead) + asm("OP_SWAP OP_CAT") + push(tail) + asm("OP_CAT")
    decode = _parent_record()
    return (
        # [left record, right record or empty, verifier funding, prevouts, ALL preimage].
        asm("OP_DEPTH OP_5 OP_NUMEQUALVERIFY OP_DUP") + authenticate_forkid_preimage() + asm("OP_DROP")
        + asm("OP_OVER OP_SIZE 144 OP_NUMEQUALVERIFY OP_HASH256 OP_OVER")
        + _slice(4, 32) + asm("OP_EQUALVERIFY OP_OVER") + _slice(36, 36)
        + asm("OP_OVER") + _slice(68, 36) + asm("OP_EQUALVERIFY")
        # The actual verifier script field and executing companion field form the dictionary.
        + asm("OP_2 OP_ROLL OP_2 OP_PICK") + _slice(0, 36) + _funding_field()
        + asm("OP_NIP OP_DUP OP_SHA256") + push(sha256(blob(verifier_lock)).digest()) + asm("OP_EQUALVERIFY")
        + asm("OP_SWAP 104 OP_SPLIT OP_NIP OP_SIZE 52 OP_SUB OP_SPLIT OP_DROP OP_DUP OP_SHA256")
        + expected_body
        # [left record, right record, prevouts, verifier field, companion field, expected token body].
        + asm("OP_5 OP_PICK OP_3 OP_PICK OP_3 OP_PICK") + decode
        + asm("OP_OVER OP_OVER OP_6 OP_PICK") + _slice(72, 36) + _same_token_lock() + asm("OP_DROP")
        # An empty right record uses the same raw bytes, still checking its actual txid and vout.
        + asm("OP_5 OP_PICK OP_SIZE OP_0 OP_NUMEQUAL OP_IF OP_DROP OP_DUP OP_ELSE OP_4 OP_PICK OP_4 OP_PICK")
        + decode + asm("OP_ENDIF OP_NIP OP_4 OP_PICK") + _slice(108, 36) + _same_token_lock()
        + asm("OP_2DROP OP_2DROP OP_2DROP OP_1")
    )


def _funded_output(tx, index, funding):
    current = tx.inputs[index]
    if (current.txid != funding.txid_wire() or current.vout != 0 or len(funding.inputs) != 1
            or len(funding.outputs) != 1 or len(funding.inputs[0].script) >= 253):
        raise ValueError("expected the actual one-input one-output funding at vout zero")
    return funding.outputs[0]


def companion_parent_material(verifier_script, companion_script, parents):
    """Return only the two parent record pushes for ordered `(parent, vout)` pairs."""
    (left, _), (right, _) = parents
    left_raw = left.serialize()
    right_raw = left_raw if right is left else right.serialize()
    if max(len(left_raw), len(right_raw)) > MAX_PARENT_BYTES:
        raise ValueError("decoded parent exceeds the Script limit")
    dictionary = blob(verifier_script), blob(companion_script)
    left_record = encode_capacity_record(left_raw, dictionary)
    right_record = b"" if left_raw == right_raw else encode_capacity_record(right_raw, dictionary)
    if max(len(left_record), len(right_record)) > MAX_PARENT_BYTES:
        raise ValueError("encoded parent record exceeds the Script limit")
    return push(left_record) + push(right_record)


def companion_witness(tx, verifier_funding, companion_funding, parents):
    """Encode the compact companion witness for actual conservation vin2 and vin3."""
    if len(tx.inputs) != 4 or len(tx.outputs) != 3:
        raise ValueError("expected the four-input, three-output conservation transaction")
    verifier = _funded_output(tx, 0, verifier_funding)
    companion = _funded_output(tx, 1, companion_funding)
    if companion.script != companion_lock(verifier.script):
        raise ValueError("expected the compact companion for the actual verifier lock")
    parents = tuple(parents)
    for current, (parent, vout) in zip(tx.inputs[2:], parents, strict=True):
        if (current.txid != parent.txid_wire() or current.vout != vout or not 0 <= vout < len(parent.outputs)):
            raise ValueError("expected the actual token parent at the designated outpoint")
    prevouts = b"".join(txin.outpoint() for txin in tx.inputs)
    preimage = preimage_all(tx, 1, companion.value, companion.script)
    return (companion_parent_material(verifier.script, companion.script, parents)
            + b"".join(map(push, (verifier_funding.serialize(), prevouts, preimage))))

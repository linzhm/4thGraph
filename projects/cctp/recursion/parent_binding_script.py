"""Script fragments for consuming independent parent transaction binding proofs."""
from mimo_verifier import _compact_size, _split, _unsigned
from parent_binding import PARENT_BINDING_DOMAIN
from shared.script import asm, number, push
from statement import fixed
from transfer import digest_limbs_script
from verifier import locking_script


def _size(expected):
    return asm("OP_SIZE") + number(expected) + asm("OP_NUMEQUALVERIFY")


def _check_output_count(max_outputs):
    if type(max_outputs) is not int or not 1 <= max_outputs <= 257:
        raise ValueError("expected a bounded parent output limit from 1 to 257")
    return number(1) + number(max_outputs + 1) + asm("OP_WITHIN OP_VERIFY")


def parent_binding_limbs_script(asset_id, *, max_outputs=257):
    """Consume [approved verifier hash, sighash byte, txid wire, outputs, count LE, digest]."""
    prefix = PARENT_BINDING_DOMAIN + fixed(asset_id, 32)
    return (
        _size(32) + asm("OP_OVER") + _size(4) + _unsigned() + _check_output_count(max_outputs)
        + asm("OP_4 OP_PICK OP_DUP") + push(b"\x41") + asm("OP_EQUAL OP_SWAP")
        + push(b"\x61") + asm("OP_EQUAL OP_BOOLOR OP_VERIFY")
        + asm("OP_CAT OP_SWAP OP_HASH256 OP_SWAP OP_CAT OP_OVER") + _size(32) + asm("OP_DROP OP_CAT OP_CAT")
        + asm("OP_OVER") + _size(32) + asm("OP_DROP OP_CAT")
        + push(prefix) + asm("OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script()
    )


def select_bound_output_script(max_outputs):
    """Consume [output fields, count LE, numeric vout]; leave [satoshis LE, lock]."""
    count = _check_output_count(max_outputs)
    # Each iteration carries [remaining outputs, target index, selected
    # satoshis and script, output cursor]. Walk the entire disclosed vector.
    step = (
        asm("OP_3 OP_PICK OP_0NOTEQUAL OP_IF") + _split(8) + _compact_size()
        + asm("OP_SPLIT OP_TOALTSTACK OP_CAT OP_2 OP_PICK OP_0 OP_NUMEQUAL OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF")
        + asm("OP_ROT OP_1SUB OP_ROT OP_1SUB OP_ROT OP_FROMALTSTACK OP_ENDIF")
    )
    return (
        asm("OP_SWAP") + _size(4) + _unsigned() + asm("OP_DUP") + count
        + asm("OP_OVER OP_0 OP_2 OP_PICK OP_WITHIN OP_VERIFY OP_SWAP OP_0 OP_3 OP_ROLL")
        + step * max_outputs
        + asm("OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP OP_ROT OP_0 OP_NUMEQUALVERIFY OP_NIP") + _split(8)
    )


def parent_binding_proof_gate(key, asset_id, *, max_outputs=257):
    """Check one binding and return [satoshis LE, lock, parent continuity digest].

    Input above the Groth16 witness is [approved verifier hash, sighash byte,
    actual prevout, output fields, count LE, parent digest]. The enclosing
    covenant supplies the hash from its authenticated asset policy and the
    prevout from its authenticated current transaction.
    """
    if len(key.ic) != 3:
        raise ValueError("parent binding key requires two public limbs")
    proof_check, _, _ = locking_script(key, None, projective_g1=True, projective_g2=True, reuse_constants=True)
    return (
        asm("OP_DUP OP_TOALTSTACK OP_2 OP_PICK OP_2 OP_PICK OP_5 OP_PICK") + _size(36)
        + _split(32) + asm("OP_NIP") + _unsigned() + select_bound_output_script(max_outputs)
        + asm("OP_CAT OP_TOALTSTACK OP_3 OP_ROLL") + _split(32) + asm("OP_DROP")
        + asm("OP_3 OP_ROLL") * 3 + parent_binding_limbs_script(asset_id, max_outputs=max_outputs)
        + proof_check + asm("OP_VERIFY OP_FROMALTSTACK") + _split(8) + asm("OP_FROMALTSTACK")
    )

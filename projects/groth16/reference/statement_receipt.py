"""Verify Groth16 limbs from the actual statement receipt of a two-vin spend.

The application binds the digest to its own rules, for example by deriving and
checking the same receipt in vin0. This validator checks the proof and actual
transaction framing of the receipt at vout1.
"""

from bsb22 import verifier_fields as committed_fields
from bsb22 import verifier_lock as committed_lock
from public_inputs import verification_key_point
from shared.script import asm, number, push
from shared.transaction import Output, blob, compact, preimage_all
from transfer import (
    COMPACT_SCRIPTCODE, COMPACT_SUFFIX, compact_preimage_digest_script, compact_verifier_binding, digest_limbs_script,
)
from verifier import locking_script, unlocking_fields, unlocking_script


RECEIPT_TAG = b"BSV/Groth16/statement/v1\x00"
DIGEST_SIZE = 32
_SCRIPT_PREFIX = asm("OP_0 OP_RETURN") + push(RECEIPT_TAG) + bytes([DIGEST_SIZE])
RECEIPT_PREFIX = bytes(8) + compact(len(_SCRIPT_PREFIX) + DIGEST_SIZE) + _SCRIPT_PREFIX
RECEIPT_SIZE = len(RECEIPT_PREFIX) + DIGEST_SIZE


def receipt_output(digest: bytes) -> Output:
    """Serialize the statement digest as the only payload of a zero-satoshi receipt."""
    if type(digest) is not bytes or len(digest) != DIGEST_SIZE:
        raise ValueError("expected a 32-byte Groth16 statement digest")
    return Output(0, _SCRIPT_PREFIX + digest)


def receipt_digest(output: Output) -> bytes:
    """Read the exact receipt payload without accepting alternate push encodings."""
    if (type(output.value) is not int or output.value != 0 or not output.script.startswith(_SCRIPT_PREFIX)
            or len(output.script) != len(_SCRIPT_PREFIX) + DIGEST_SIZE):
        raise ValueError("expected a canonical Groth16 statement receipt")
    return output.script[len(_SCRIPT_PREFIX):]


def _split(offset):
    return number(offset) + asm("OP_SPLIT")


def _slice(offset, length):
    return _split(offset) + asm("OP_NIP") + _split(length) + asm("OP_DROP")


def _skip_output():
    """Skip one exact TxOut using its canonical CompactSize length (up to uint32)."""
    unsigned = push(b"\x00") + asm("OP_CAT OP_BIN2NUM")
    return (
        asm("OP_8 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP") + unsigned
        + asm("OP_DUP 253 OP_LESSTHAN OP_NOTIF")
        + asm("OP_DUP 253 OP_NUMEQUAL OP_IF OP_DROP OP_2 OP_SPLIT OP_SWAP") + unsigned
        + asm("OP_DUP 252 OP_GREATERTHAN OP_VERIFY OP_ELSE")
        + asm("254 OP_NUMEQUALVERIFY OP_4 OP_SPLIT OP_SWAP") + unsigned
        + asm("OP_DUP 65535 OP_GREATERTHAN OP_VERIFY OP_ENDIF OP_ENDIF OP_SPLIT OP_NIP")
    )


def statement_script():
    """Consume [outputs, prevouts, compact vin1 preimage] and leave two limbs."""
    script_field = blob(COMPACT_SCRIPTCODE)
    return (
        # Preserve the digest of this very preimage for the final CHECKSIG.
        asm("OP_DUP") + compact_preimage_digest_script() + asm("OP_DROP OP_DUP")
        + _slice(104, len(script_field)) + push(script_field) + asm("OP_EQUALVERIFY")
        # Require two actual outpoints and bind the executing input to vin1.
        + asm("OP_OVER OP_SIZE 72 OP_NUMEQUALVERIFY OP_HASH256 OP_OVER")
        + _slice(4, 32) + asm("OP_EQUALVERIFY OP_OVER 36 OP_SPLIT OP_NIP OP_OVER")
        + _slice(68, 36) + asm("OP_EQUALVERIFY OP_NIP")
        # Authenticate all output fields and require the receipt to be last.
        + asm("OP_OVER OP_HASH256 OP_OVER") + _slice(152, 32) + asm("OP_EQUALVERIFY OP_DROP")
        + _skip_output() + _split(len(RECEIPT_PREFIX)) + asm("OP_SWAP")
        + push(RECEIPT_PREFIX) + asm("OP_EQUALVERIFY OP_SIZE 32 OP_NUMEQUALVERIFY")
        + digest_limbs_script()
    )


def verifier_lock(key, commitment=None):
    """Build the vin1 lock, with either a plain or a single-commitment Groth16 key."""
    if commitment is None:
        if len(key.ic) != 3:
            raise ValueError("a plain statement verifier requires two public limbs")
        proof_lock = locking_script(key, None, projective_g1=True, projective_g2=True, reuse_constants=True)[0]
    else:
        if len(key.ic) != 4:
            raise ValueError("a committed statement verifier requires two public limbs and a commitment")
        proof_lock = committed_lock(key, commitment)
    return statement_script() + proof_lock + compact_verifier_binding()


def verifier_material(tx, funding):
    """Serialize the transaction material after the proof fields in vin1."""
    if len(tx.inputs) != 2 or len(tx.outputs) != 2:
        raise ValueError("statement verifier requires exactly two inputs and two outputs")
    receipt_digest(tx.outputs[1])
    current = tx.inputs[1]
    if current.txid != funding.txid_wire() or not 0 <= current.vout < len(funding.outputs):
        raise ValueError("funding does not match the actual statement verifier outpoint")
    previous = funding.outputs[current.vout]
    if not previous.script.endswith(COMPACT_SUFFIX):
        raise ValueError("expected a compact binding suffix in the verifier funding lock")
    preimage = preimage_all(tx, 1, previous.value, COMPACT_SCRIPTCODE)
    return b"".join(map(push, (
        b"".join(output.serialize() for output in tx.outputs),
        b"".join(item.outpoint() for item in tx.inputs),
        preimage,
    )))


def verifier_witness(key, proof, tx, funding, commitment=None):
    """Encode proof fields using the two digest limbs declared by the receipt."""
    material = verifier_material(tx, funding)
    digest = receipt_digest(tx.outputs[1])
    signals = int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")
    if commitment is None:
        point = verification_key_point(key.ic, signals) or (0, 0)
        fields = unlocking_fields(key, signals, proof, projective_g1=True, projective_g2=True)
        fields = (*point, *fields)
    else:
        fields = committed_fields(key, commitment, signals, proof)
    return unlocking_script(fields) + material

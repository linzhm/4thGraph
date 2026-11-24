"""Experimental one-lock freeze proof, funded and tested on an isolated asset."""
from hashlib import sha256

from bsb22 import verifier_lock as committed_lock
from mimo_verifier import _match_prefix, _split
from parent_preimage import _compact_size
from shared.script import asm, number, push
from shared.transaction import Output, blob, hash256, preimage_forkid
from statement import fixed, public_inputs
from transfer import authenticate_forkid_preimage, digest_limbs_script
from verifier import locking_script


DOMAIN = b"BSV/CCTP/freeze-transition/v1\x00"
TOKEN_MARKER = push(b"BSV/CCTP/freeze-probe/v1\x00")
METADATA_SIZE = 74
METADATA_PREFIX = TOKEN_MARKER + bytes([METADATA_SIZE])
FLAG_OFFSET = len(METADATA_PREFIX) + METADATA_SIZE - 1
SINGLE = 0x43
ALL = 0x41


def _state(output):
    script = output.script
    if not script.startswith(METADATA_PREFIX) or len(script) <= FLAG_OFFSET:
        raise ValueError("expected the isolated freeze probe lock")
    normalized = script[:FLAG_OFFSET] + bytes(1) + script[FLAG_OFFSET + 1:]
    return output.value.to_bytes(8, "little") + script[len(METADATA_PREFIX):FLAG_OFFSET + 1] + sha256(blob(normalized)).digest()


def statement(tx, previous, *, paired_index=0):
    if paired_index != 0 or len(tx.inputs) != 2 or len(tx.outputs) != 1:
        raise ValueError("expected token vin0, fee vin1 and paired vout0")
    preimage = preimage_forkid(tx, paired_index, previous.value, previous.script, SINGLE)
    return (
        DOMAIN + tx.inputs[paired_index].outpoint() + paired_index.to_bytes(4, "little") + hash256(preimage)
        + _state(previous) + _state(tx.outputs[paired_index])
    )


def signals(tx, previous):
    return public_inputs(statement(tx, previous))


def transaction_witness(tx, previous, signer):
    """Append the native role authorization and actual transaction binding to the proof witness."""
    statement(tx, previous)
    full = preimage_forkid(tx, 0, previous.value, previous.script, ALL)
    return (
        push(signer(hash256(full)) + bytes([ALL])) + push(b"".join(item.outpoint() for item in tx.inputs))
        + push(tx.outputs[0].serialize()) + push(full)
    )


def _state_script():
    """Convert [sats8, serialized script field] to a canonical public state record."""
    return (
        asm("OP_DUP OP_TOALTSTACK") + _compact_size()
        + asm("OP_OVER OP_SIZE OP_NIP OP_NUMEQUALVERIFY OP_SIZE OP_TOALTSTACK")
        + _match_prefix(METADATA_PREFIX) + _split(METADATA_SIZE) + asm("OP_DROP OP_CAT")
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_SIZE OP_ROT OP_SUB")
        + number(FLAG_OFFSET) + asm("OP_ADD OP_SPLIT OP_1 OP_SPLIT OP_NIP")
        + push(bytes(1)) + asm("OP_SWAP OP_CAT OP_CAT OP_SHA256 OP_CAT")
    )


def transaction_statement_script(freeze_key):
    """Verify authorization and derive limbs from the actual token input and paired output."""
    return (
        asm("OP_DUP") + authenticate_forkid_preimage(ALL) + asm("OP_DROP")
        # Bind the actual vin order and require the executing token at vin0.
        + asm("OP_2 OP_PICK OP_SIZE 72 OP_NUMEQUALVERIFY OP_DUP OP_HASH256 OP_2 OP_PICK")
        + _split(4) + asm("OP_NIP 32 OP_SPLIT OP_DROP OP_EQUALVERIFY 36 OP_SPLIT OP_DROP OP_OVER")
        + _split(68) + asm("OP_NIP 36 OP_SPLIT OP_DROP OP_EQUALVERIFY")
        # Comparing the one exact paired output to ALL excludes extra outputs.
        + asm("OP_DUP OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP OP_2 OP_PICK OP_HASH256 OP_EQUALVERIFY")
        + asm("OP_3 OP_ROLL OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP") + push(bytes([ALL]))
        + asm("OP_EQUALVERIFY") + push(fixed(freeze_key, 33)) + asm("OP_CHECKSIGVERIFY")
        # Rebuild the statement's SINGLE digest from the authenticated singleton
        # output. SINGLE zeroes hashSequence and changes the trailing type only.
        + asm("OP_DUP 36 OP_SPLIT 32 OP_SPLIT OP_NIP OP_SWAP") + push(bytes(32))
        + asm("OP_CAT OP_SWAP OP_CAT OP_SIZE OP_4 OP_SUB OP_SPLIT OP_DROP")
        + push(SINGLE.to_bytes(4, "little")) + asm("OP_CAT OP_HASH256 OP_TOALTSTACK")
        # Decode the real spent script and amount from the authenticated preimage.
        + _split(104) + asm("OP_NIP OP_SIZE 52 OP_SUB OP_SPLIT OP_8 OP_SPLIT OP_DROP OP_SWAP")
        + _state_script() + asm("OP_SWAP OP_8 OP_SPLIT") + _state_script()
        + asm("OP_2 OP_ROLL 36 OP_SPLIT OP_DROP") + push(bytes(4))
        + asm("OP_CAT OP_FROMALTSTACK OP_CAT OP_ROT OP_CAT OP_SWAP OP_CAT")
        + push(DOMAIN) + asm("OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script()
    )


def lock(state, freeze_key, verifying_key, relation=None):
    """Build the isolated issuer-only token lock containing its proof verifier."""
    verifier = (
        locking_script(verifying_key, None, projective_g1=True, projective_g2=True, reuse_constants=True)[0]
        if relation is None else committed_lock(verifying_key, relation)
    )
    return (
        METADATA_PREFIX + fixed(state.encode(), METADATA_SIZE) + asm("OP_2DROP")
        + transaction_statement_script(freeze_key) + verifier
    )


def paired_successor(previous):
    """Copy the exact lock and spent satoshis, changing just the state bit."""
    _state(previous)
    script = previous.script
    if script[FLAG_OFFSET] not in (0, 1):
        raise ValueError("invalid prior freeze state")
    toggled = bytes([script[FLAG_OFFSET] ^ 1])
    return Output(previous.value, script[:FLAG_OFFSET] + toggled + script[FLAG_OFFSET + 1:])

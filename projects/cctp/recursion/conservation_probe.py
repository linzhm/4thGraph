"""Isolated CCTP 2→2 token shell for one shared conservation proof."""

from hashlib import sha256

from mimo_verifier import _match_prefix, _split
from parent_preimage import _compact_size, _skip_output
from shared.script import asm, number, push
from shared.transaction import amount, blob, hash256, preimage_forkid
from statement import fixed, uint
from statement_receipt import RECEIPT_PREFIX, receipt_output as statement_receipt
from transfer import shared_guard_lock, verifier_input_script_hash


DOMAIN = b"BSV/CCTP/conservation/v1\x00"
METADATA_SIZE = 74
METADATA_PREFIX = push(b"BSV/CCTP/conservation-token/v1\x00") + bytes([METADATA_SIZE])
STATE_SIZE = 114
CONTEXT_SIZE = 104
OWNER_OFFSET = 48
ALL = 0x41


def state_record(output):
    """Encode the actual amount, metadata and hash of the normalized script field."""
    offset = len(METADATA_PREFIX)
    end = offset + METADATA_SIZE
    script = output.script
    if not script.startswith(METADATA_PREFIX) or len(script) <= end:
        raise ValueError("expected a conservation probe token lock")
    normalized = script[:offset] + bytes(METADATA_SIZE) + script[end:]
    return amount(output.value) + script[offset:end] + sha256(blob(normalized)).digest()


def _prevouts(tx):
    return b"".join(item.outpoint() for item in tx.inputs)


def statement(tx, previous_outputs):
    """Encode the common statement from two prior TxOuts in vin2/vin3 order."""
    if len(tx.inputs) != 4 or len(tx.outputs) not in (2, 3) or len(previous_outputs) != 2:
        raise ValueError("expected verifier vin0, companion vin1, two token inputs and two token outputs")
    pairs = tx.outputs[:2]
    return (
        DOMAIN + uint(tx.version, 4) + hash256(_prevouts(tx))
        + hash256(b"".join(uint(item.sequence, 4) for item in tx.inputs))
        + hash256(b"".join(output.serialize() for output in pairs)) + uint(tx.locktime, 4)
        + b"".join(state_record(output) for output in (*previous_outputs, *pairs))
    )


def receipt_output(tx, previous_outputs):
    return statement_receipt(hash256(statement(tx, previous_outputs)))


def token_witness(tx, index, previous_outputs, companion_funding, signer):
    """Request the holder ALL signature and serialize compact token-side material."""
    if type(index) is not int or index not in (2, 3):
        raise ValueError("expected token input vin 2 or 3")
    receipt = receipt_output(tx, previous_outputs)
    if len(tx.outputs) != 3 or receipt != tx.outputs[2]:
        raise ValueError("expected exact conservation statement receipt at vout 2")
    if (tx.inputs[1].txid != companion_funding.txid_wire() or tx.inputs[1].vout != 0
            or len(companion_funding.inputs) != 1 or len(companion_funding.inputs[0].script) >= 253
            or len(companion_funding.outputs) != 1):
        raise ValueError("expected actual one-input one-output companion funding at vin 1, vout 0")
    previous = previous_outputs[index - 2]
    full = preimage_forkid(tx, index, previous.value, previous.script, ALL)
    return b"".join(map(push, (
        signer(hash256(full)) + bytes([ALL]), companion_funding.serialize(), _prevouts(tx),
        b"".join(state_record(output) for output in previous_outputs),
        b"".join(output.serialize() for output in tx.outputs), full,
    )))


def _slice(offset, length):
    return _split(offset) + asm("OP_NIP") + _split(length) + asm("OP_DROP")


def _select_prior_slot():
    """Check the real current outpoint and save whether it occupies vin3."""
    return (
        asm("OP_DEPTH OP_6 OP_NUMEQUALVERIFY OP_3 OP_PICK OP_SIZE 144 OP_NUMEQUALVERIFY 72 OP_SPLIT OP_NIP 36 OP_SPLIT"
            " OP_2 OP_PICK")
        + _slice(68, 36) + asm("OP_TUCK OP_EQUAL OP_TOALTSTACK OP_EQUAL OP_FROMALTSTACK"
                               " OP_DUP OP_TOALTSTACK OP_NUMEQUAL OP_NOT OP_VERIFY")
    )


def _take_output():
    """Return one serialized TxOut and the remainder of the output vector."""
    return (asm("OP_DUP") + _skip_output()
            + asm("OP_SIZE OP_2 OP_PICK OP_SIZE OP_NIP OP_SWAP OP_SUB OP_NIP OP_SPLIT"))


def state_record_script():
    """From [sats8, serialized script field], leave the canonical state record."""
    return (
        asm("OP_DUP OP_TOALTSTACK") + _compact_size()
        + asm("OP_OVER OP_SIZE OP_NIP OP_NUMEQUALVERIFY OP_SIZE OP_TOALTSTACK")
        + _match_prefix(METADATA_PREFIX) + _split(METADATA_SIZE) + asm("OP_SIZE OP_0NOTEQUAL OP_VERIFY OP_DROP OP_CAT")
        # Locate metadata through the canonical script-field length, retaining every other byte.
        + asm("OP_FROMALTSTACK OP_FROMALTSTACK OP_SIZE OP_ROT OP_SUB") + number(len(METADATA_PREFIX))
        + asm("OP_ADD OP_SPLIT") + _split(METADATA_SIZE) + asm("OP_NIP")
        + push(bytes(METADATA_SIZE)) + asm("OP_SWAP OP_CAT OP_CAT OP_SHA256 OP_CAT")
    )


def _holder_check():
    """Bind our actual slot and authenticate its original metadata's holder."""
    return (
        # [holder signature, two prior records, actual outputs, ALL preimage].
        asm("OP_DUP 104 OP_SPLIT OP_NIP OP_SIZE 52 OP_SUB OP_SPLIT OP_8 OP_SPLIT OP_DROP OP_SWAP")
        + state_record_script()
        + asm("OP_3 OP_PICK OP_SIZE") + number(2 * STATE_SIZE) + asm("OP_NUMEQUALVERIFY")
        + _split(STATE_SIZE) + asm("OP_FROMALTSTACK OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF OP_OVER OP_EQUALVERIFY")
        + _slice(OWNER_OFFSET, 33) + asm("OP_4 OP_ROLL OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
        + push(bytes([ALL])) + asm("OP_EQUALVERIFY OP_SWAP OP_CHECKSIGVERIFY")
    )


def _receipt_check():
    """Compare the actual context, both ordered prior records and successors to the receipt."""
    return (
        # [two prior records, outputs, preimage] becomes [prior records, preimage, vout0, vout1].
        asm("OP_SWAP") + _take_output() * 2 + _match_prefix(RECEIPT_PREFIX)
        + asm("OP_SIZE 32 OP_NUMEQUALVERIFY OP_TOALTSTACK")
        # Reconstruct the 104-byte context. The actual receipt remains excluded from the inner hashOutputs.
        + asm("OP_2 OP_PICK 68 OP_SPLIT OP_DROP OP_2 OP_PICK OP_2 OP_PICK OP_CAT OP_HASH256 OP_CAT OP_3 OP_ROLL"
              " OP_SIZE OP_8 OP_SUB OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_DROP OP_CAT OP_TOALTSTACK")
        + asm("OP_SWAP OP_8 OP_SPLIT") + state_record_script()
        + asm("OP_SWAP OP_8 OP_SPLIT") + state_record_script()
        + asm("OP_CAT OP_CAT OP_FROMALTSTACK OP_SWAP OP_CAT") + push(DOMAIN)
        + asm("OP_SWAP OP_CAT OP_HASH256 OP_FROMALTSTACK OP_EQUAL")
    )


def token_statement_script(companion_script_field_hash):
    """Bind the real holder, companion and conserved statement from transaction evidence."""
    return (
        _select_prior_slot()
        # Authenticate the complete ALL preimage and actual vin1 funding, using the executing token input.
        + asm("OP_4 OP_ROLL OP_4 OP_ROLL OP_2 OP_PICK") + verifier_input_script_hash(input_index=1)
        + push(fixed(companion_script_field_hash, 32)) + asm("OP_EQUALVERIFY")
        + asm("OP_DUP OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP OP_2 OP_PICK OP_HASH256 OP_EQUALVERIFY")
        + _holder_check() + _receipt_check()
    )


def lock(state, verifier_lock=None, *, companion_lock=None):
    """Build a token lock pinning one exact companion lock and its verifier policy."""
    if (verifier_lock is None) == (companion_lock is None):
        raise ValueError("supply either a complete verifier lock or its complete companion lock")
    approved = verifier_lock if companion_lock is None else companion_lock
    if type(approved) is not bytes or not approved:
        raise ValueError("expected a complete locking script")
    if companion_lock is None:
        approved = shared_guard_lock(approved)
    return (
        METADATA_PREFIX + fixed(state.encode(), METADATA_SIZE) + asm("OP_2DROP")
        + token_statement_script(sha256(blob(approved)).digest())
    )

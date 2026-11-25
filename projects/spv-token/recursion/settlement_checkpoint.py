"""Reconstruct the fixed-width settlement prefix and its SHA-256 checkpoint."""

from dataclasses import dataclass
from hashlib import sha256

from covenant_backtrace import _slice
from mimo_verifier import _pick
from parent_prefix import BLOCK_BYTES, sha256_continue
from route_a_funding import reconstruction_script
from shared.script import asm, number, push
from shared.transaction import blob, compact


DROP = asm("OP_DROP")
CAT = asm("OP_CAT")

COMPANION_BYTES = 847
FUNDING_HEAD = 127
G_CONTEXT = 1021  # Encoded ordered prevouts and full companion ForkID preimage.
G_TRAILER = 7 + G_CONTEXT  # CAT, pushed four-byte locktime, CAT, context.
G_OVERHEAD = 2 + FUNDING_HEAD + G_TRAILER
CLAIM_BYTES = 1 + 36 + FUNDING_HEAD + G_TRAILER + 36
META_BYTES = 73
PREFIX_OVERHEAD = 5 + 36 + 5 + G_OVERHEAD + 4 + 36 + 5 + 5 + 1
MIN_PROGRAM = 65_536
MAX_PROGRAM = 250_000
PAYMENT_HEADER = b"\x02\0\0\0\x04"
SEQUENCE = b"\xff" * 4


def funding_program(funding):
    """Return a funding reconstruction and its payer-independent code."""
    if len(funding.inputs) != 1 or len(funding.outputs) != 1 or len(funding.inputs[0].script) >= 253:
        raise ValueError("expected the canonical single-output verifier funding layout")
    raw = funding.serialize()
    lock = blob(funding.outputs[0].script)
    static = reconstruction_script(lock)
    head = raw[:-len(lock)-4]
    tail = raw[-4:]
    return push(head) + static + CAT + push(tail) + CAT, static


def _padding(length):
    return b"\x80" + bytes((55 - length) % BLOCK_BYTES) + (length * 8).to_bytes(8, "big")


def checkpointed_companion(tx, leading_script, trailing_script):
    """Return the new vin0 script and the unpadded prefix length of its wire tx."""
    head_width = 4 + len(compact(len(tx.inputs))) + 36
    for length_width in (1, 3, 5, 9):
        prefix_width = head_width + length_width + len(leading_script) + 1
        padding = _padding(prefix_width)
        script = leading_script + push(padding) + DROP + trailing_script
        if len(compact(len(script))) == length_width:
            return script, prefix_width
    raise ValueError("could not align companion input to a SHA-256 boundary")


def continue_padded_transaction(raw, prefix_width):
    """Return the real wire txid when the serialized prefix includes its padding."""
    padding = _padding(prefix_width)
    processed = prefix_width + len(padding)
    if prefix_width <= 0 or raw[prefix_width:processed] != padding:
        raise ValueError("transaction does not have canonical padding at the checkpoint")
    state = sha256(raw[:prefix_width]).digest()
    return sha256(sha256_continue(state, processed, raw[processed:])).digest()


@dataclass(frozen=True)
class Opening:
    point: bytes
    units: int
    claim: bytes
    meta: bytes
    private: bytes


def _funding_unlock(head, program, locktime, context):
    """Rejoin a payer's funding fields with the policy's fixed verifier template."""
    return push(head) + program + asm("OP_CAT") + push(locktime) + asm("OP_CAT") + context


def _script_slot(remainder, inactive, *, max_program=MAX_PROGRAM):
    """Transform one fixed-width [claim, program] into its authenticated metadata."""
    return (
        asm("OP_OVER") + _slice(0, 1) + push(b"\x01") + asm("OP_EQUAL OP_IF OP_SIZE OP_DUP")
        + number(MIN_PROGRAM) + number(max_program + 1) + asm("OP_WITHIN OP_VERIFY")
        # Compute the prefix boundary, padding byte count, and processed length.
        + asm("OP_2 OP_MUL") + number(PREFIX_OVERHEAD) + asm("OP_ADD OP_DUP 64 OP_MOD 119 OP_SWAP OP_SUB 64 OP_MOD 9 OP_ADD")
        + asm("OP_2DUP OP_ADD OP_4 OP_NUM2BIN OP_TOALTSTACK OP_SWAP OP_DROP")
        # Stack is [claim, program, padding size], with the growing prefix on top.
        + _pick(2) + _slice(1, 36) + push(PAYMENT_HEADER) + asm("OP_SWAP OP_CAT")
        + _pick(2) + asm("OP_SIZE OP_NIP") + number(G_OVERHEAD) + asm("OP_ADD OP_4 OP_NUM2BIN")
        + push(b"\xfe") + asm("OP_SWAP OP_CAT OP_CAT") + push(b"\x4c\x7f") + asm("OP_CAT")
        + _pick(3) + _slice(37, FUNDING_HEAD) + asm("OP_CAT") + _pick(2) + asm("OP_CAT")
        + _pick(3) + _slice(37 + FUNDING_HEAD, G_TRAILER) + asm("OP_CAT")
        + push(SEQUENCE) + asm("OP_CAT") + _pick(3) + _slice(CLAIM_BYTES - 36, 36) + asm("OP_CAT")
        + _pick(2) + asm("OP_SIZE OP_NIP") + _pick(2) + asm("OP_ADD")
        + number(7 + remainder) + asm("OP_ADD OP_4 OP_NUM2BIN") + push(b"\xfe") + asm("OP_SWAP OP_CAT OP_CAT")
        + _pick(2) + asm("OP_SIZE OP_NIP OP_4 OP_NUM2BIN") + push(b"\x4e") + asm("OP_SWAP OP_CAT OP_CAT")
        + _pick(2) + asm("OP_CAT OP_OVER OP_1 OP_NUM2BIN OP_CAT OP_SHA256 OP_FROMALTSTACK OP_CAT")
        + _pick(3) + _slice(1, 36) + asm("OP_CAT") + push(b"\x01") + asm("OP_SWAP OP_CAT")
        + asm("OP_TOALTSTACK OP_2DROP OP_DROP OP_FROMALTSTACK OP_ELSE OP_DROP")
        + inactive + asm("OP_ENDIF")
    )


def _prefix(claim, program, remainder, *, max_program=MAX_PROGRAM):
    if len(claim) != CLAIM_BYTES or claim[0] != 1 or not MIN_PROGRAM <= len(program) <= max_program:
        raise ValueError("invalid settlement prefix layout")
    checkpoint = 2 * len(program) + PREFIX_OVERHEAD
    padding = _padding(checkpoint)
    source = claim[1:37]
    head = claim[37:37 + FUNDING_HEAD]
    rest = claim[37 + FUNDING_HEAD:-36]
    prefix = (PAYMENT_HEADER + source + compact(len(program) + G_OVERHEAD)
              + push(head) + program + rest + SEQUENCE + claim[-36:]
              + compact(len(program) + 7 + len(padding) + remainder) + push(program) + bytes([len(padding)]))
    if len(prefix) != checkpoint:
        raise ValueError("noncanonical settlement prefix")
    return prefix, padding

"""Canonical wide receipts and compact proof contexts reconstructed from actual parent bytes."""
from dataclasses import dataclass

from continuity_preimage import CURRENT_AMOUNT, CURRENT_OUTPOINT, _funding_output, continuity_digest
from continuity_statement import PARENT_SIZE, ParentReceipt, ZERO
from mimo_verifier import _compact_size, _match_prefix, _split, _unsigned
from shared.script import asm, number, push
from shared.transaction import Output, blob, compact
from statement import fixed

CAPACITY_SHAPES = {16: (1, 1), 17: (1, 64), 18: (64, 64), 19: (1, 256), 20: (256, 256)}
CAPACITY_TAG = b"BSV/CCTP/capacity-receipt/v1\x00"
CONTEXT_PREFIX_SIZE = 152
CONTEXT_SUFFIX_SIZE = 8
CONTEXT_SIZE = CONTEXT_PREFIX_SIZE + CONTEXT_SUFFIX_SIZE
RECEIPT_BODY_SIZE = 1 + PARENT_SIZE + CONTEXT_SIZE
RECEIPT_MARKER = asm("OP_0 OP_RETURN") + push(CAPACITY_TAG) + push(bytes(RECEIPT_BODY_SIZE))[:-RECEIPT_BODY_SIZE]
CAPACITY_OUTPUT_PREFIX = bytes(8) + compact(len(RECEIPT_MARKER) + RECEIPT_BODY_SIZE) + RECEIPT_MARKER
CAPACITY_OUTPUT_SIZE = len(CAPACITY_OUTPUT_PREFIX) + RECEIPT_BODY_SIZE


def context_material(preimage: bytes) -> bytes:
    raw = fixed(preimage, CONTEXT_SIZE + 32)
    return raw[:CONTEXT_PREFIX_SIZE] + raw[-CONTEXT_SUFFIX_SIZE:]


@dataclass(frozen=True)
class CapacityReceipt:
    mode: int
    ancestry: ParentReceipt
    material: bytes

    def output(self):
        if type(self.mode) is not int or self.mode not in CAPACITY_SHAPES or not self.ancestry.parents:
            raise ValueError("invalid capacity receipt mode or ancestry")
        return Output(0, RECEIPT_MARKER + bytes([self.mode]) + self.ancestry.payload() + fixed(self.material, CONTEXT_SIZE))

    @classmethod
    def matches(cls, output):
        return output.script.startswith(RECEIPT_MARKER)

    @classmethod
    def parse(cls, output):
        if output.value != 0 or not cls.matches(output):
            raise ValueError("missing canonical capacity receipt")
        data = fixed(output.script[len(RECEIPT_MARKER):], RECEIPT_BODY_SIZE)
        payload = data[1:1 + PARENT_SIZE]
        count = payload[0]
        if count not in (1, 2) or (count == 1 and payload[-32:] != ZERO):
            raise ValueError("invalid capacity ancestry payload")
        receipt = cls(data[0], ParentReceipt(tuple(payload[1 + i*32:33 + i*32] for i in range(count))),
                      data[1 + PARENT_SIZE:])
        if receipt.output() != output:
            raise ValueError("noncanonical capacity receipt")
        return receipt


def _last(size):
    return asm("OP_SIZE") + number(size) + asm("OP_SUB OP_SPLIT OP_NIP")


def _slice(offset, size):
    return _split(offset) + asm("OP_NIP") + _split(size) + asm("OP_DROP")


def _receipt_tail():
    return _last(CAPACITY_OUTPUT_SIZE + 4) + _split(CAPACITY_OUTPUT_SIZE) + asm("OP_DROP")


def is_capacity_parent_script():
    """Consume a raw transaction copy, leaving a capacity receipt marker test."""
    return (
        asm("OP_SIZE") + number(CAPACITY_OUTPUT_SIZE + 4) + asm("OP_LESSTHAN OP_IF OP_DROP OP_0 OP_ELSE")
        + _receipt_tail() + _split(len(CAPACITY_OUTPUT_PREFIX)) + asm("OP_DROP")
        + push(CAPACITY_OUTPUT_PREFIX) + asm("OP_EQUAL OP_ENDIF")
    )


def _receipt_body():
    return _receipt_tail() + _match_prefix(CAPACITY_OUTPUT_PREFIX)


def _by_mode(modes, branch):
    code = b""
    for mode in modes[:-1]:
        code += (asm("OP_DUP") + number(mode) + asm("OP_NUMEQUAL OP_IF OP_DROP")
                 + branch(*CAPACITY_SHAPES[mode]) + asm("OP_ELSE"))
    code += number(modes[-1]) + asm("OP_NUMEQUALVERIFY") + branch(*CAPACITY_SHAPES[modes[-1]])
    return code + asm("OP_ENDIF") * (len(modes) - 1)


def _skip_input():
    return (_split(36) + asm("OP_NIP") + _compact_size()
            + asm("OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_NIP"))


def _capacity_outputs(incoming, outgoing, token_script_size):
    stride = 8 + len(compact(token_script_size)) + token_script_size
    outputs_size = outgoing * stride + CAPACITY_OUTPUT_SIZE
    return (
        asm("OP_4 OP_SPLIT OP_NIP") + _match_prefix(compact(incoming + 2)) + _skip_input() * (incoming + 2)
        + _match_prefix(compact(outgoing + 1)) + asm("OP_SIZE") + number(outputs_size + 4)
        + asm("OP_NUMEQUALVERIFY") + _split(outputs_size) + asm("OP_DROP")
    )


def _narrow_parent_outputs():
    skip = asm("OP_DUP OP_0NOTEQUAL OP_IF OP_SWAP") + _skip_input() + asm("OP_SWAP OP_1SUB OP_ENDIF")
    return (
        asm("OP_4 OP_SPLIT OP_NIP") + _compact_size() + asm("OP_DUP 1 5 OP_WITHIN OP_VERIFY")
        + skip * 4 + asm("OP_0 OP_NUMEQUALVERIFY") + _compact_size() + asm("OP_DUP 1 5 OP_WITHIN OP_VERIFY")
        + asm("OP_SWAP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_DROP")
    )


def parent_outputs_script(modes, token_script_size):
    """Consume the exact raw parent and leave its output count and full output vector."""
    def outputs(incoming, outgoing):
        return _capacity_outputs(incoming, outgoing, token_script_size) + number(outgoing + 1) + asm("OP_SWAP")

    return (
        asm("OP_DUP") + is_capacity_parent_script() + asm("OP_IF OP_DUP")
        + _receipt_body() + asm("OP_1 OP_SPLIT OP_DROP") + _unsigned() + _by_mode(modes, outputs)
        + asm("OP_ELSE") + _narrow_parent_outputs() + asm("OP_ENDIF")
    )


def capacity_parent_digest_script(modes, token_script_size, asset_id, key_digest):
    """Consume [actual wide parent raw, its actual funding raw, lock hash].

    The confirmed parent spent this exact verifier, which checked the receipt
    against its authenticated compact preimage. Re-derive the actual output
    hash and authenticate that spent verifier's vin and amount before reusing
    the parent's already-checked context fields.
    """
    def outputs_and_vin(incoming, outgoing):
        return (
            asm("OP_DUP") + _capacity_outputs(incoming, outgoing, token_script_size)
            + asm("OP_SWAP OP_4 OP_SPLIT OP_NIP") + _match_prefix(compact(incoming + 2))
            + _split(36) + asm("OP_DROP")
        )

    return (
        asm("OP_2 OP_PICK") + _receipt_body() + asm("OP_1 OP_SPLIT OP_SWAP") + _unsigned()
        + asm("OP_4 OP_PICK OP_SWAP") + _by_mode(modes, outputs_and_vin)
        # The receipt stores the compact input context with no hashOutputs.
        # The actual spending input and its amount still come from its prevout.
        + asm("OP_DUP OP_3 OP_PICK") + _slice(PARENT_SIZE + CURRENT_OUTPOINT, 36) + asm("OP_EQUALVERIFY")
        + asm("OP_4 OP_ROLL OP_SWAP") + _funding_output() + asm("OP_4 OP_ROLL OP_EQUALVERIFY")
        + asm("OP_2 OP_PICK") + _slice(PARENT_SIZE + CURRENT_AMOUNT, 8) + asm("OP_EQUALVERIFY")
        + asm("OP_HASH256 OP_ROT OP_DROP OP_SWAP") + _split(PARENT_SIZE)
        + _split(CONTEXT_PREFIX_SIZE) + asm("OP_TOALTSTACK OP_ROT OP_CAT OP_FROMALTSTACK OP_CAT OP_HASH256")
        + continuity_digest(asset_id, key_digest)
    )


def verify_capacity_receipt_script(mode):
    """Consume [actual serialized output, compact preimage, expected ancestry]."""
    return (
        asm("OP_DUP OP_2 OP_PICK") + _split(CONTEXT_PREFIX_SIZE) + _split(32)
        + asm("OP_NIP OP_CAT OP_CAT") + push(CAPACITY_OUTPUT_PREFIX + bytes([mode]))
        + asm("OP_SWAP OP_CAT OP_3 OP_ROLL OP_EQUALVERIFY OP_SWAP")
    )

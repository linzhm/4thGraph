"""Wire commitments shared by the continuity circuit and a BSV transaction."""
from dataclasses import dataclass

from shared.script import asm, push
from shared.transaction import Output, compact, hash256
from statement import fixed, public_inputs

CONTINUITY_DOMAIN = b"BSV/CCTP/continuity/v1\x00"
RECEIPT_TAG = b"BSV/CCTP/continuity-parents/v1\x00"
PARENT_SIZE = 65
ZERO = bytes(32)
RECEIPT_PREFIX = asm("OP_0 OP_RETURN") + push(RECEIPT_TAG) + bytes([PARENT_SIZE])
OUTPUT_PREFIX = bytes(8) + compact(len(RECEIPT_PREFIX) + PARENT_SIZE) + RECEIPT_PREFIX
OUTPUT_SIZE = len(OUTPUT_PREFIX) + PARENT_SIZE


@dataclass(frozen=True)
class ParentReceipt:
    """Commit the ordered prior proof digests in the last zero-satoshi output.

    The receipt excludes this transaction's own digest, so the transaction can
    commit to the receipt without a self-referential hash.
    """
    parents: tuple[bytes, ...]

    def payload(self):
        if len(self.parents) > 2:
            raise ValueError("at most two recursive predecessors")
        return bytes([len(self.parents)]) + b"".join(fixed(item, 32) for item in self.parents) + ZERO * (2 - len(self.parents))

    def output(self):
        return Output(0, RECEIPT_PREFIX + self.payload())

    @classmethod
    def parse(cls, output):
        if output.value != 0 or not output.script.startswith(RECEIPT_PREFIX):
            raise ValueError("missing canonical continuity receipt")
        payload = fixed(output.script[len(RECEIPT_PREFIX):], PARENT_SIZE)
        count = payload[0]
        if count > 2 or any(payload[1 + 32 * count:]):
            raise ValueError("invalid predecessor count or padding")
        return cls(tuple(payload[1 + 32*i:33 + 32*i] for i in range(count)))

    def statement(self, asset_id, key_digest, transaction_context):
        return (
            CONTINUITY_DOMAIN + fixed(asset_id, 32) + fixed(key_digest, 32)
            + fixed(transaction_context, 32) + self.payload()
        )

    def digest(self, asset_id, key_digest, transaction_context):
        return hash256(self.statement(asset_id, key_digest, transaction_context))

    def signals(self, asset_id, key_digest, transaction_context):
        return public_inputs(self.statement(asset_id, key_digest, transaction_context))

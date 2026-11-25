"""Public statement for the verifier funding checkpoint."""

from dataclasses import dataclass
from hashlib import sha256

from checkpoint_verifier import _size, _slice
from mimo_verifier import _split
from parent_prefix import BLOCK_BYTES, output_offsets, sha256_checkpoint, sha256_continue
from shared.script import asm, push
from shared.transaction import Transaction, amount, blob, hash256
from transfer import compact_preimage_digest_script

DOMAIN = b"BSV/CCTP/verifier-funding-checkpoint/v1\0"
MIN_FUNDING_BYTES = 60
MAX_FUNDING_BYTES = 1_000_000
CHECKPOINT_HEADER_BYTES = 8 + 3 * 4 + 32


def statement_script(approved_lock_hash):
    """Derive the statement digest at vin 1 in a four-input spend.

    Stack inputs are the checkpoint disclosure, ordered prevouts and compact
    ForkID ALL preimage. The caller must check the digest with its proof
    verifier and execute compact_verifier_binding() to finish CHECKSIG.
    """
    if len(approved_lock_hash) != 32:
        raise ValueError("expected the policy lock hash")
    return (
        asm("OP_DUP") + compact_preimage_digest_script() + asm("OP_DROP")
        + asm("OP_OVER") + _size(144) + asm("OP_HASH256 OP_OVER") + _slice(4, 32) + asm("OP_EQUALVERIFY")
        + asm("OP_OVER") + _slice(36, 36) + asm("OP_OVER") + _slice(68, 36) + asm("OP_EQUALVERIFY OP_DROP")
        + _slice(0, 36) + push(DOMAIN) + asm("OP_SWAP OP_CAT") + push(approved_lock_hash) + asm("OP_CAT OP_SWAP")
        + _split(CHECKPOINT_HEADER_BYTES) + asm("OP_HASH256 OP_CAT OP_CAT OP_HASH256")
    )


@dataclass(frozen=True)
class FundingCheckpoint:
    value: int
    output_count_offset: int
    length: int
    processed: int
    state: bytes
    suffix: bytes

    def encode(self):
        amount_wire = amount(self.value)
        if (self.value == 0 or not MIN_FUNDING_BYTES <= self.length <= MAX_FUNDING_BYTES
                or not 46 <= self.output_count_offset < self.length - 13
                or self.processed != self.length - self.length % BLOCK_BYTES
                or len(self.state) != 32 or len(self.suffix) != self.length - self.processed):
            raise ValueError("invalid funding checkpoint encoding")
        return (amount_wire + self.output_count_offset.to_bytes(4, "little") + self.length.to_bytes(4, "little")
                + self.processed.to_bytes(4, "little") + self.state + self.suffix)

    def continued_txid_wire(self):
        return sha256(sha256_continue(self.state, self.processed, self.suffix)).digest()

    def digest(self, actual_outpoint, approved_lock_hash):
        """Use outpoint from the actual spend and the lock hash from the policy."""
        if len(actual_outpoint) != 36 or len(approved_lock_hash) != 32:
            raise ValueError("expected a serialized outpoint and the policy lock hash")
        return hash256(DOMAIN + actual_outpoint + approved_lock_hash + self.encode()[:CHECKPOINT_HEADER_BYTES]
                       + hash256(self.suffix))


def from_funding(raw):
    """Generate a disclosure and lock hash from a finalized funding transaction."""
    if not MIN_FUNDING_BYTES <= len(raw) <= MAX_FUNDING_BYTES:
        raise ValueError("funding transaction outside the supported size")
    tx = Transaction.parse(raw)
    if len(tx.inputs) != 1 or len(tx.inputs[0].script) >= 253 or len(tx.outputs) != 1:
        raise ValueError("unsupported verifier funding layout")
    output = tx.outputs[0]
    if not output.script:
        raise ValueError("missing verifier lock")
    count_offset, _ = output_offsets(raw)
    processed = len(raw) - len(raw) % BLOCK_BYTES
    checkpoint = FundingCheckpoint(output.value, count_offset, len(raw), processed,
                                   sha256_checkpoint(raw[:processed]), raw[processed:])
    checkpoint.encode()
    if checkpoint.continued_txid_wire() != tx.txid_wire():
        raise ValueError("full txid and SHA-256 checkpoint disagree")
    return checkpoint, sha256(blob(output.script)).digest()

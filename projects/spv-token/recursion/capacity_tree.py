"""Same-key proof hierarchy for authenticated, ordered wide-transaction parents.

The transaction relation supplies one proof digest per actual creating
transaction, in canonical prevout order. It validates the real token inputs
and the receipt output independently. The hierarchy only packages predecessor
proofs for the existing two-slot continuity statement.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TypeVar

from continuity_preimage import continuity_digest
from continuity_statement import ParentReceipt, ZERO
from shared.script import asm, push
from shared.transaction import hash256
from statement import fixed

CAPACITY_TREE_DOMAIN = b"BSV/CCTP/capacity-tree/v1\x00"
MAX_CAPACITY = 256

ProofArtifact = TypeVar("ProofArtifact")


@dataclass(frozen=True)
class CapacityStep:
    """One synthetic context to prove under the same continuity key."""

    context: bytes
    receipt: ParentReceipt
    digest: bytes


@dataclass(frozen=True)
class CapacityPlan:
    """The payment receipt and each distinct synthetic proof in dependency order."""

    parent_digests: tuple[bytes, ...]
    receipt: ParentReceipt
    steps: tuple[CapacityStep, ...]

    def prove(
        self,
        parent_artifacts: Iterable[ProofArtifact],
        callback: Callable[[bytes, tuple[ProofArtifact, ...]], ProofArtifact],
    ) -> tuple[ProofArtifact, ...]:
        """Prove synthetic contexts and return the payment's predecessor artifacts.

        The input artifacts follow the same order as the actual parent digests.
        The callback receives the synthetic context and its two ordered children.
        """
        artifacts = dict(zip(self.parent_digests, parent_artifacts, strict=True))
        for step in self.steps:
            children = tuple(artifacts[digest] for digest in step.receipt.parents)
            artifacts[step.digest] = callback(step.context, children)
        return tuple(artifacts[digest] for digest in self.receipt.parents)


def _check_parameters(asset_id, key_digest, capacity):
    fixed(asset_id, 32)
    fixed(key_digest, 32)
    if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY or capacity & (capacity - 1):
        raise ValueError(f"capacity must be a power of two from 1 to {MAX_CAPACITY}")


def _context_prefix(height):
    return CAPACITY_TREE_DOMAIN + bytes([height])


def capacity_plan(asset_id: bytes, key_digest: bytes, capacity: int,
                  parent_digests: Iterable[bytes]) -> CapacityPlan:
    """Pad with the last digest and compute the two root children.

    A singleton uses its original proof directly. The height byte starts at one
    for the first level of synthetic nodes. Predecessor proofs for identical
    padded subtrees can be generated once and reused.
    """
    _check_parameters(asset_id, key_digest, capacity)
    parents = tuple(fixed(digest, 32) for digest in parent_digests)
    if not 1 <= len(parents) <= capacity:
        raise ValueError("parent digest count is outside the capacity")
    if len(parents) == 1:
        return CapacityPlan(parents, ParentReceipt(parents), ())

    level = parents + (parents[-1],) * (capacity - len(parents))
    steps = {}
    for height in range(1, capacity.bit_length() - 1):
        next_level = []
        for left, right in zip(level[::2], level[1::2], strict=True):
            receipt = ParentReceipt((left, right))
            context = hash256(_context_prefix(height) + left + right)
            digest = receipt.digest(asset_id, key_digest, context)
            steps.setdefault(digest, CapacityStep(context, receipt, digest))
            next_level.append(digest)
        level = tuple(next_level)
    return CapacityPlan(parents, ParentReceipt(level), tuple(steps.values()))


def capacity_receipt(asset_id: bytes, key_digest: bytes, capacity: int,
                     parent_digests: Iterable[bytes]) -> ParentReceipt:
    return capacity_plan(asset_id, key_digest, capacity, parent_digests).receipt


def _fold_level(digest_script, height, width):
    # Split each consecutive pair, hash its synthetic context, then wrap that
    # context and its children in an ordinary two-parent continuity statement.
    pair = (
        asm("64 OP_SPLIT OP_TOALTSTACK OP_DUP")
        + push(_context_prefix(height))
        + asm("OP_SWAP OP_CAT OP_HASH256 OP_2 OP_ROT OP_CAT OP_SWAP")
        + digest_script
    )
    return (
        pair + asm("OP_FROMALTSTACK")
        + (pair + asm("OP_CAT OP_FROMALTSTACK")) * (width // 2 - 1)
        + asm("OP_DROP")
    )


def capacity_receipt_script(asset_id: bytes, key_digest: bytes, capacity: int) -> bytes:
    """Consume a packed digest vector and leave the exact 65-byte receipt payload."""
    _check_parameters(asset_id, key_digest, capacity)
    single = asm("OP_1 OP_SWAP OP_CAT") + push(ZERO) + asm("OP_CAT")
    if capacity == 1:
        return asm("OP_SIZE 32 OP_NUMEQUALVERIFY") + single

    max_bytes = capacity * 32
    height_limit = capacity.bit_length() - 1
    checks = asm(
        f"OP_SIZE OP_DUP 32 OP_MOD OP_0 OP_NUMEQUALVERIFY "
        f"OP_DUP 32 {max_bytes + 1} OP_WITHIN OP_VERIFY"
    )
    # Build a string of last-digest copies, trim it to the deficit, and append.
    pad = (
        asm("OP_DUP 32 OP_SUB OP_2 OP_PICK OP_SWAP OP_SPLIT OP_NIP")
        + asm("OP_DUP OP_CAT") * height_limit
        + asm(f"OP_SWAP {max_bytes} OP_SWAP OP_SUB OP_SPLIT OP_DROP OP_CAT")
    )
    digest_script = continuity_digest(asset_id, key_digest)
    levels = b"".join(
        _fold_level(digest_script, height, capacity >> (height - 1))
        for height in range(1, height_limit)
    )
    return (
        checks + asm("OP_DUP 32 OP_NUMEQUAL OP_IF OP_DROP") + single
        + asm("OP_ELSE") + pad + levels + asm("OP_2 OP_SWAP OP_CAT OP_ENDIF")
    )

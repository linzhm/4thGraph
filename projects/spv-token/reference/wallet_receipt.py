"""Wallet verification of a designated BSV token output and its confirmation."""
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from shared.transaction import Transaction, hash256
from statement import AssetDescriptor, fixed


class SpendStatus(Enum):
    UNKNOWN = "unknown"
    UNSPENT = "unspent"
    SPENT = "spent"


@dataclass(frozen=True)
class BlockInclusion:
    """Merkle branch with txids/siblings and block hash in BSV wire order."""
    header: bytes
    height: int
    index: int
    leaf_count: int
    siblings: tuple[bytes, ...]

    def block_hash(self) -> bytes:
        return hash256(fixed(self.header, 80))

    def verify(self, txid_wire: bytes) -> None:
        txid = fixed(txid_wire, 32)
        index, width = self.index, self.leaf_count
        if (type(index) is not int or type(width) is not int
                or not 0 <= index < width <= 0xffffffff):
            raise ValueError("invalid Merkle position")
        for sibling in self.siblings:
            fixed(sibling, 32)
            if width <= 1:
                raise ValueError("excess Merkle sibling")
            if (index ^ 1) >= width:
                if sibling != txid:
                    raise ValueError("wrong duplicate-last Merkle sibling")
            elif sibling == txid:
                raise ValueError("mutated Merkle branch")
            txid = hash256(sibling + txid if index & 1 else txid + sibling)
            index //= 2
            width = (width + 1) // 2
        if width != 1 or txid != fixed(self.header, 80)[36:68]:
            raise ValueError("invalid transaction Merkle inclusion")

    @classmethod
    def from_block(cls, header, height, txids, index):
        """Derive a portable branch from the full transaction list for a block."""
        if type(index) is not int or not 0 <= index < len(txids):
            raise ValueError("invalid Merkle position")
        layer = tuple(fixed(txid, 32) for txid in txids)
        selected = layer[index]
        position, siblings = index, []
        while len(layer) > 1:
            siblings.append(layer[position ^ 1] if (position ^ 1) < len(layer) else layer[position])
            paired = layer if len(layer) % 2 == 0 else (*layer, layer[-1])
            layer = tuple(hash256(paired[i] + paired[i + 1]) for i in range(0, len(paired), 2))
            position //= 2
        inclusion = cls(header, height, index, len(txids), tuple(siblings))
        inclusion.verify(selected)
        return inclusion


@dataclass(frozen=True)
class WalletReceipt:
    outpoint: bytes
    quantity: int
    owner: bytes
    frozen: bool
    confirmations: int
    spend_status: SpendStatus


def verify_payment(
    transaction: Transaction, vout: int, asset: AssetDescriptor, policy, inclusion: BlockInclusion,
    *, adopted_depth: Callable[[int, bytes], int | None],
    valid_creation: Callable[[Transaction, int], bool],
    lookup_spend: Callable[[bytes], SpendStatus],
    minimum_confirmations: int = 1, expected_owner: bytes | None = None,
) -> WalletReceipt:
    """Verify inclusion in the wallet's adopted header chain.

    valid_creation must authenticate the exact vout against the mint/transition
    rules and the asset's provenance. A lock-template match is insufficient.
    The adopted_depth callback returns None for blocks outside the adopted
    chain. Spend state is independent and may be unknown.
    """
    if type(vout) is not int or not 0 <= vout < len(transaction.outputs):
        raise ValueError("invalid payment vout")
    state = policy.parse(transaction.outputs[vout].script)
    if state is None or state.asset_id != asset.asset_id():
        raise ValueError("wrong asset or token lock")
    if expected_owner is not None and state.owner != fixed(expected_owner, 33):
        raise ValueError("wrong token owner")
    txid_wire = transaction.txid_wire()
    inclusion.verify(txid_wire)
    if (type(inclusion.height) is not int or inclusion.height < 0
            or type(minimum_confirmations) is not int or minimum_confirmations < 1):
        raise ValueError("invalid confirmation policy")
    depth = adopted_depth(inclusion.height, inclusion.block_hash())
    if type(depth) is not int or depth < minimum_confirmations:
        raise ValueError("block outside the adopted chain or not confirmed")
    if valid_creation(transaction, vout) is not True:
        raise ValueError("unauthenticated output creation")
    outpoint = txid_wire + vout.to_bytes(4, "little")
    status = lookup_spend(outpoint)
    if not isinstance(status, SpendStatus):
        raise ValueError("invalid known spend status")
    return WalletReceipt(outpoint, state.quantity, state.owner, state.frozen, depth, status)

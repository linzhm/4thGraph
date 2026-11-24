"""Wire commitments for a bounded CCTP inventory and a two-input payment."""

from dataclasses import dataclass

from shared.transaction import amount, hash256
from statement import fixed, uint


@dataclass(frozen=True)
class InventoryState:
    quantity: int
    sats: int
    owner: bytes
    frozen: bool = False

    def encode(self):
        quantity = uint(self.quantity, 8)
        sats = amount(self.sats)
        owner = fixed(self.owner, 33)
        if self.quantity == 0 or self.sats == 0 or owner[0] not in (2, 3) or type(self.frozen) is not bool:
            raise ValueError("invalid inventory token state")
        return quantity + sats + owner + bytes([self.frozen])


@dataclass(frozen=True)
class InventoryLeaf:
    scope: bytes
    outpoint: bytes
    state: InventoryState

    def digest(self):
        return hash256(b"\x00" + fixed(self.scope, 32) + fixed(self.outpoint, 36) + self.state.encode())


def pair_digest(left, right):
    return hash256(b"\x01" + fixed(left, 32) + fixed(right, 32))


def _levels(leaves):
    """The protocol fixes tree width separately from transaction history."""
    leaves = tuple(leaves)
    if not leaves or len(leaves) & (len(leaves) - 1):
        raise ValueError("inventory width must be a power of two")
    if len({leaf.scope for leaf in leaves}) != 1 or len({leaf.outpoint for leaf in leaves}) != len(leaves):
        raise ValueError("expected one scope and distinct outpoints")
    current = tuple(leaf.digest() for leaf in leaves)
    yield current
    while len(current) > 1:
        current = tuple(pair_digest(current[i], current[i + 1]) for i in range(0, len(current), 2))
        yield current


def inventory_root(leaves):
    return tuple(_levels(leaves))[-1][0]


def membership_path(leaves, index):
    levels = tuple(_levels(leaves))
    if type(index) is not int or not 0 <= index < len(levels[0]):
        raise ValueError("inventory index out of range")
    return tuple(level[(index >> height) ^ 1] for height, level in enumerate(levels[:-1]))


def payment_digest(scope, root, input_outpoints, outputs):
    if len(input_outpoints) != 2 or len(set(input_outpoints)) != 2 or len(outputs) != 2:
        raise ValueError("expected two distinct outpoints and two ordered outputs")
    return hash256(b"\x02" + fixed(scope, 32) + fixed(root, 32)
                   + b"".join(fixed(outpoint, 36) for outpoint in input_outpoints)
                   + b"".join(state.encode() for state in outputs))


def _positions(width, positions):
    positions = tuple(positions)
    if type(width) is not int or width <= 0 or width & (width - 1) or not positions:
        raise ValueError("invalid inventory width or empty selection")
    if any(type(i) is not int or not 0 <= i < width for i in positions):
        raise ValueError("inventory position out of range")
    if positions != tuple(sorted(set(positions))):
        raise ValueError("expected strictly increasing inventory positions")
    return positions


def _walk(height, index, occupied, hidden, opened):
    """Visit only occupied branches, taking unopened subtree roots in wire order."""
    if (height, index) not in occupied:
        return hidden(height, index)
    if height == 0:
        return opened(index)
    left = _walk(height - 1, index * 2, occupied, hidden, opened)
    right = _walk(height - 1, index * 2 + 1, occupied, hidden, opened)
    return pair_digest(left, right)


def _occupied(width, positions):
    return {(height, index >> height) for index in _positions(width, positions)
            for height in range(width.bit_length())}


def multi_path(leaves, positions):
    """Sibling hashes in depth-first (left-first) order; indices travel separately."""
    levels = tuple(_levels(leaves))
    width = len(levels[0])
    siblings = []

    def take_hidden(height, index):
        value = levels[height][index]
        siblings.append(value)
        return value

    _walk(len(levels) - 1, 0, _occupied(width, positions), take_hidden, levels[0].__getitem__)
    return tuple(siblings)


def open_multi_path(width, positions, digests, siblings):
    positions = _positions(width, positions)
    nodes = dict(zip(positions, (fixed(item, 32) for item in digests), strict=True))
    siblings = iter(siblings)
    end = object()

    def take_hidden(height, index):
        value = next(siblings, end)
        if value is end:
            raise ValueError("missing inventory sibling")
        return fixed(value, 32)

    root = _walk(width.bit_length() - 1, 0, _occupied(width, positions), take_hidden, nodes.__getitem__)
    if next(siblings, end) is not end:
        raise ValueError("trailing inventory sibling")
    return root

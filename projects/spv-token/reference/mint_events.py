"""Canonical deposits and a sparse commitment to consumed deposit events."""

from dataclasses import dataclass
from functools import cached_property

from shared.transaction import hash256
from statement import fixed, uint

DEPOSIT_DOMAIN = b"BSV/CCTP/deposit/v1\0"
EVENT_ID_DOMAIN = b"BSV/CCTP/deposit-id/v1\0"
LEAF_DOMAIN = b"BSV/CCTP/mint-leaf/v1\0"
NODE_DOMAIN = b"BSV/CCTP/mint-node/v1\0"
EMPTY_LEAF = hash256(LEAF_DOMAIN + b"\0")
SPENT_LEAF = hash256(LEAF_DOMAIN + b"\1")
TREE_DEPTH = 256


def _branch(left: bytes, right: bytes) -> bytes:
    return hash256(NODE_DOMAIN + left + right)


def _empty_hashes() -> tuple[bytes, ...]:
    levels = [EMPTY_LEAF]
    for _ in range(TREE_DEPTH):
        levels.append(_branch(levels[-1], levels[-1]))
    return tuple(levels)


EMPTY_HASHES = _empty_hashes()
EMPTY_ROOT = EMPTY_HASHES[-1]


@dataclass(frozen=True)
class DepositPosition:
    source_chain_id: int
    reserve_domain: int
    reserve_contract: bytes
    transaction_hash: bytes
    log_ordinal: int

    def encode(self) -> bytes:
        return (
            uint(self.source_chain_id, 8)
            + uint(self.reserve_domain, 4)
            + fixed(self.reserve_contract, 20)
            + fixed(self.transaction_hash, 32)
            + uint(self.log_ordinal, 4)
        )

    def event_id(self) -> bytes:
        return hash256(EVENT_ID_DOMAIN + self.encode())


def compressed_key(key: bytes) -> bytes:
    from ecdsa import SECP256k1, VerifyingKey
    from ecdsa.errors import MalformedPointError

    fixed(key, 33)
    if key[0] not in (2, 3):
        raise ValueError("expected compressed secp256k1 public key")
    try:
        VerifyingKey.from_string(key, curve=SECP256k1, valid_encodings={"compressed"})
    except (MalformedPointError, ValueError) as error:
        raise ValueError("invalid secp256k1 public key") from error
    return key


@dataclass(frozen=True)
class Deposit:
    position: DepositPosition
    reserve_asset: bytes
    destination_network: int
    asset_id: bytes
    gross_quantity: int
    fee_quantity: int
    owner: bytes

    @property
    def net_quantity(self) -> int:
        uint(self.gross_quantity, 8)
        uint(self.fee_quantity, 8)
        if self.fee_quantity >= self.gross_quantity:
            raise ValueError("deposit must have positive net quantity")
        return self.gross_quantity - self.fee_quantity

    def encode(self) -> bytes:
        self.net_quantity
        return (
            self.position.encode()
            + fixed(self.reserve_asset, 32)
            + uint(self.destination_network, 4)
            + fixed(self.asset_id, 32)
            + uint(self.gross_quantity, 8)
            + uint(self.fee_quantity, 8)
            + compressed_key(self.owner)
        )

    @classmethod
    def parse(cls, raw: bytes) -> "Deposit":
        fixed(raw, DEPOSIT_SIZE)

        def value(start, stop):
            return int.from_bytes(raw[start:stop], "little")

        position = DepositPosition(value(0, 8), value(8, 12), raw[12:32], raw[32:64], value(64, 68))
        deposit = cls(position, raw[68:100], value(100, 104), raw[104:136],
                      value(136, 144), value(144, 152), raw[152:185])
        deposit.encode()
        return deposit


POSITION_SIZE = 68
GROSS_OFFSET = 136
FEE_OFFSET = 144
OWNER_OFFSET = 152
DEPOSIT_SIZE = 185


def transition_roots(event_id: bytes, path: tuple[bytes, ...]) -> tuple[bytes, bytes]:
    """Fold the same proof from an empty leaf and the occupied leaf."""
    index = int.from_bytes(fixed(event_id, 32), "little")
    if len(path) != TREE_DEPTH:
        raise ValueError("incorrect sparse Merkle proof length")
    before, after = EMPTY_LEAF, SPENT_LEAF
    for sibling in path:
        fixed(sibling, 32)
        if index & 1:
            before, after = _branch(sibling, before), _branch(sibling, after)
        else:
            before, after = _branch(before, sibling), _branch(after, sibling)
        index >>= 1
    return before, after


@dataclass(frozen=True)
class MintEvents:
    """Reference replay set. Authority remains with the root committed on chain."""

    consumed: frozenset[bytes] = frozenset()

    def __post_init__(self):
        if not isinstance(self.consumed, frozenset):
            raise ValueError("consumed event IDs must be immutable")
        for event_id in self.consumed:
            fixed(event_id, 32)

    @cached_property
    def _levels(self) -> tuple[dict[int, bytes], ...]:
        values = {int.from_bytes(event_id, "little"): SPENT_LEAF for event_id in self.consumed}
        levels = [values]
        for empty in EMPTY_HASHES[:-1]:
            values = {
                i: _branch(values.get(i * 2, empty), values.get(i * 2 + 1, empty))
                for i in {index >> 1 for index in values}
            }
            levels.append(values)
        return tuple(levels)

    @property
    def root(self) -> bytes:
        return self._levels[-1].get(0, EMPTY_ROOT)

    def add(self, event_id: bytes) -> tuple["MintEvents", tuple[bytes, ...]]:
        index = int.from_bytes(fixed(event_id, 32), "little")
        if event_id in self.consumed:
            raise ValueError("deposit event was already consumed")
        path = tuple(
            self._levels[level].get((index >> level) ^ 1, EMPTY_HASHES[level])
            for level in range(TREE_DEPTH)
        )
        return MintEvents(self.consumed | {event_id}), path

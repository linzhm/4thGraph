"""Counted native mint policy for two or three fixed lab deposit events."""

from dataclasses import dataclass, field
from functools import cached_property

from mint import MintPolicy, _size
from mint_events import MintEvents
from shared.script import asm, push
from statement import fixed


BOUNDED_STATE_MARKER = push(b"BSV/CCTP/mint-state/b1\0")


@dataclass(frozen=True)
class BoundedMintPolicy(MintPolicy):
    """Use the exact sparse roots of a finite, immutable set of lab events."""

    state_version: int = field(default=2, kw_only=True)
    event_ids: tuple[bytes, ...] = field(kw_only=True)

    def __post_init__(self):
        super().__post_init__()
        if self.state_version != 2:
            raise ValueError("bounded lab mint requires a counted state")
        if type(self.event_ids) is not tuple or len(self.event_ids) not in (2, 3):
            raise ValueError("expected two or three immutable lab deposit event IDs")
        ids = tuple(sorted(fixed(event_id, 32) for event_id in self.event_ids))
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate lab deposit event ID")
        object.__setattr__(self, "event_ids", ids)

    @property
    def state_marker(self) -> bytes:
        return BOUNDED_STATE_MARKER

    @cached_property
    def _event_transitions(self) -> tuple[tuple[bytes, bytes], ...]:
        roots = tuple(
            MintEvents(frozenset(event_id for i, event_id in enumerate(self.event_ids) if mask & (1 << i))).root
            for mask in range(1 << len(self.event_ids))
        )
        if len(set(roots)) != len(roots):
            raise ValueError("duplicate sparse root in bounded lab mint")
        return tuple(
            (root + event_id, roots[mask | (1 << i)])
            for mask, root in enumerate(roots)
            for i, event_id in enumerate(self.event_ids)
            if not mask & (1 << i)
        )

    def _event_transition(self, events: MintEvents, event_id: bytes) -> tuple[MintEvents, tuple[bytes, ...]]:
        successor, path = super()._event_transition(events, event_id)
        if (events.root + event_id, successor.root) not in self._event_transitions:
            raise ValueError("deposit event or predecessor is outside the bounded lab mint")
        return successor, path

    def _event_path_bytes(self, path: tuple[bytes, ...]) -> bytes:
        return b""

    def _event_transition_script(self) -> bytes:
        rows = tuple(
            asm("OP_DUP") + push(key) + asm("OP_EQUAL OP_IF OP_DROP") + push(successor) + asm("OP_ELSE")
            for key, successor in self._event_transitions
        )
        # Retain the default witness slot as an empty value. The authenticated
        # old root and full event hash form the only lookup key.
        return (
            asm("OP_6 OP_PICK") + _size(0) + asm("OP_DROP OP_CAT")
            + b"".join(rows) + asm("OP_0 OP_VERIFY") + asm("OP_ENDIF") * len(rows)
        )

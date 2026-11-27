"""Bounded ordered experiments over explicit optimization states."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar


MAX_ORDER_DEPTH = 8
MAX_ORDER_STATES = 256
DEFAULT_ORDER_STATES = 64
State = TypeVar("State")


class IneligibleMethod(ValueError):
    """A method's precondition does not hold at this point in a plan."""


@dataclass(frozen=True)
class Method(Generic[State]):
    region: str
    requires: str
    apply: Callable[[State], State]


def explore_orders(seed, methods, *, describe, evaluate, max_depth=MAX_ORDER_DEPTH, max_states=DEFAULT_ORDER_STATES):
    """Expand distinct compiler states breadth-first and retain all tried edges.

    The state's hash and equality must cover every fact that can affect a subsequent
    method. Exact artifact identity is for evaluation, never for graph expansion.
    """
    if type(max_depth) is not int or not 1 <= max_depth <= MAX_ORDER_DEPTH:
        raise ValueError(f"method search depth must be between 1 and {MAX_ORDER_DEPTH}")
    if type(max_states) is not int or not 1 <= max_states <= MAX_ORDER_STATES:
        raise ValueError(f"method search state budget must be between 1 and {MAX_ORDER_STATES}")
    if not methods:
        raise ValueError("method search requires at least one registered method")

    state_ids = {seed: 0}
    queue = [(seed, ())]
    states, transitions, limits = [], [], set()
    # The first route to an equal state has the shortest prefix and leaves the
    # most remaining budget. Other incoming edges remain in the report.
    for index, (state, order) in enumerate(queue):
        states.append({"id": index, "order": list(order), "state": describe(state), **evaluate(state)})
        for name, method in methods.items():
            edge = {"from": index, "method": name}
            try:
                updated = method.apply(state)
            except IneligibleMethod as error:
                transitions.append({**edge, "status": "ineligible", "reason": str(error)})
                continue
            if updated in state_ids:
                status = "no_change" if updated == state else "equivalent"
                transitions.append({**edge, "status": status, "to": state_ids[updated]})
                continue
            if len(order) == max_depth:
                limits.add("depth")
                transitions.append({**edge, "status": "depth_budget"})
                continue
            if len(queue) == max_states:
                limits.add("states")
                transitions.append({**edge, "status": "state_budget"})
                continue
            state_ids[updated] = len(queue)
            queue.append((updated, order + (name,)))
            transitions.append({**edge, "status": "applied", "to": state_ids[updated]})

    return {"budget": {"max_depth": max_depth, "max_states": max_states},
            "stop": "budget" if limits else "exhausted", "limits_hit": sorted(limits),
            "states": states, "transitions": transitions}

"""Bounded ordered-pair experiments over explicit optimization states."""

from collections.abc import Callable
from dataclasses import dataclass
from itertools import product
from typing import Generic, TypeVar


MAX_CELLS = 64
State = TypeVar("State")


class IneligibleMethod(ValueError):
    """A method's precondition does not hold at this point in a plan."""


@dataclass(frozen=True)
class Method(Generic[State]):
    region: str
    requires: str
    apply: Callable[[State], State]


def explore_pairs(seeds, methods, *, describe, evaluate):
    """Retain every ordered plan. The caller owns compilation and verification caches."""
    cells = len(seeds) * len(methods) ** 2
    if not 1 <= cells <= MAX_CELLS:
        raise ValueError(f"ordered-pair exploration needs between 1 and {MAX_CELLS} cells")

    def run(seed, order):
        state = seed
        steps = []
        for name in order:
            try:
                updated = methods[name].apply(state)
            except IneligibleMethod as error:
                steps.append({"method": name, "status": "ineligible", "reason": str(error)})
                return {"order": list(order), "steps": steps, "status": "ineligible"}
            steps.append({"method": name, "status": "no_change" if updated == state else "applied",
                          "state": describe(updated)})
            state = updated
        return {"order": list(order), "steps": steps, **evaluate(state)}

    return {
        name: {
            "seed": describe(seed),
            "baseline": run(seed, ()),
            "cells": [run(seed, order) for order in product(methods, repeat=2)],
        }
        for name, seed in seeds.items()
    }

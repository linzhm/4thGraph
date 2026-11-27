"""Typed logical CPNs and bounded, token-count-only reachability analysis.

This module models an application's graph independently of transaction layouts.
Token colours, predicates, authorizations and timing are intentionally not
interpreted by the reachability analysis.
"""

from collections import deque
from dataclasses import dataclass, field
import json


class CPNError(ValueError):
    def __init__(self, code, path, message):
        super().__init__(f"{path}: {message}")
        self.code, self.path, self.message = code, path, message

    def diagnostic(self):
        return {"code": self.code, "path": self.path, "message": self.message}


def _object(value, path, required, optional=()):
    if not isinstance(value, dict):
        raise CPNError("invalid_object", path, "expected an object")
    missing = set(required) - value.keys()
    unknown = value.keys() - set(required) - set(optional)
    if missing:
        raise CPNError("missing_field", path, f"missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise CPNError("unknown_field", path, f"unknown fields: {', '.join(sorted(unknown))}")


def _name(value, path):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise CPNError("invalid_name", path, "expected a nonempty string without surrounding whitespace")
    return value


def _integer(value, path, minimum):
    if type(value) is not int or value < minimum:
        raise CPNError("invalid_count", path, f"expected an integer greater than or equal to {minimum}")
    return value


def _array(value, path):
    if not isinstance(value, list):
        raise CPNError("invalid_array", path, "expected an array")
    return value


def _metadata(value, path):
    if not isinstance(value, dict):
        raise CPNError("invalid_metadata", path, "expected an object")
    for name in ("visibility", "carrier"):
        if name in value:
            _name(value[name], path + "." + name)
    for name in ("constraints", "witnesses", "authorization", "evidence"):
        if name in value:
            items = _array(value[name], path + "." + name)
            if any(not isinstance(item, (str, dict)) or isinstance(item, str) and not item.strip()
                   for item in items):
                raise CPNError("invalid_metadata", path + "." + name,
                               "expected an array of nonempty strings or objects")

    def check_keys(item):
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise CPNError("invalid_metadata", path, "metadata object keys must be strings")
            for child in item.values():
                check_keys(child)
        elif isinstance(item, list):
            for child in item:
                check_keys(child)

    check_keys(value)
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as error:
        raise CPNError("invalid_metadata", path, "metadata must contain only JSON values") from error


@dataclass(frozen=True)
class Place:
    name: str
    type: str
    initial: int = 0
    capacity: int | None = None
    metadata: dict = field(default_factory=dict)

    def describe(self):
        return {"name": self.name, "type": self.type, "initial": self.initial, "capacity": self.capacity,
                "metadata": _metadata(self.metadata, "$.metadata")}


@dataclass(frozen=True)
class Arc:
    name: str
    place: str
    type: str
    count: int = 1

    def describe(self):
        return {"name": self.name, "place": self.place, "type": self.type, "count": self.count}


@dataclass(frozen=True)
class Transition:
    name: str
    inputs: tuple[Arc, ...]
    outputs: tuple[Arc, ...]
    word: str | None = None
    metadata: dict = field(default_factory=dict)

    def describe(self):
        return {"name": self.name, "word": self.word, "inputs": [arc.describe() for arc in self.inputs],
                "outputs": [arc.describe() for arc in self.outputs], "metadata": _metadata(self.metadata, "$.metadata")}


@dataclass(frozen=True)
class LogicalCPN:
    places: tuple[Place, ...]
    transitions: tuple[Transition, ...]

    def describe(self):
        return {"schema_version": 1, "places": [place.describe() for place in self.places],
                "transitions": [transition.describe() for transition in self.transitions]}


def parse_net(document):
    """Parse a logical CPN, rejecting ambiguous arcs and type mismatches."""
    _object(document, "$", ("schema_version", "places", "transitions"))
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise CPNError("schema_version", "$.schema_version", "expected schema version 1")
    places = {}
    for i, raw in enumerate(_array(document["places"], "$.places")):
        path = f"$.places[{i}]"
        _object(raw, path, ("name", "type"), ("initial", "capacity", "metadata"))
        name = _name(raw["name"], path + ".name")
        if name in places:
            raise CPNError("duplicate_place", path + ".name", f"duplicate place {name!r}")
        kind = _name(raw["type"], path + ".type")
        initial = _integer(raw.get("initial", 0), path + ".initial", 0)
        capacity = raw.get("capacity")
        if capacity is not None:
            _integer(capacity, path + ".capacity", 0)
            if initial > capacity:
                raise CPNError("capacity", path + ".initial", "initial marking exceeds place capacity")
        places[name] = Place(name, kind, initial, capacity, _metadata(raw.get("metadata", {}), path + ".metadata"))
    if not places:
        raise CPNError("empty_places", "$.places", "expected at least one place")

    transitions = {}
    for i, raw in enumerate(_array(document["transitions"], "$.transitions")):
        path = f"$.transitions[{i}]"
        _object(raw, path, ("name", "inputs", "outputs"), ("word", "metadata"))
        name = _name(raw["name"], path + ".name")
        if name in transitions:
            raise CPNError("duplicate_transition", path + ".name", f"duplicate transition {name!r}")
        word = raw.get("word")
        if word is not None:
            _name(word, path + ".word")

        def arcs(side):
            result, names, connected = [], set(), set()
            for j, item in enumerate(_array(raw[side], path + "." + side)):
                arcpath = f"{path}.{side}[{j}]"
                _object(item, arcpath, ("name", "place", "type"), ("count",))
                port = _name(item["name"], arcpath + ".name")
                place = _name(item["place"], arcpath + ".place")
                kind = _name(item["type"], arcpath + ".type")
                count = _integer(item.get("count", 1), arcpath + ".count", 1)
                if port in names:
                    raise CPNError("duplicate_port", arcpath + ".name", f"duplicate {side} port {port!r}")
                if place in connected:
                    raise CPNError("duplicate_arc", arcpath + ".place",
                                   "place already has an arc on this side; use count for multiple tokens")
                if place not in places:
                    raise CPNError("unknown_place", arcpath + ".place", f"unknown place {place!r}")
                if kind != places[place].type:
                    raise CPNError("type_mismatch", arcpath + ".type", f"expected {places[place].type!r}, got {kind!r}")
                names.add(port)
                connected.add(place)
                result.append(Arc(port, place, kind, count))
            return tuple(result)

        inputs, outputs = arcs("inputs"), arcs("outputs")
        if not inputs and not outputs:
            raise CPNError("empty_transition", path, "transition must consume or produce a token")
        transitions[name] = Transition(name, inputs, outputs, word, _metadata(raw.get("metadata", {}), path + ".metadata"))
    if not transitions:
        raise CPNError("empty_transitions", "$.transitions", "expected at least one transition")
    return LogicalCPN(tuple(places.values()), tuple(transitions.values()))


def validate_document(document):
    """Return a JSON-serializable canonical model or diagnostic."""
    try:
        return {"ok": True, "model": parse_net(document).describe(), "diagnostics": []}
    except CPNError as error:
        return {"ok": False, "model": None, "diagnostics": [error.diagnostic()]}


def analyze(net, *, max_states=1000, max_tokens_per_place=16):
    """Enumerate a bounded over-approximation of markings by token counts."""
    _integer(max_states, "$.max_states", 1)
    _integer(max_tokens_per_place, "$.max_tokens_per_place", 0)
    names = tuple(place.name for place in net.places)
    indexes = {name: i for i, name in enumerate(names)}
    initial = tuple(place.initial for place in net.places)
    if any(value > max_tokens_per_place for value in initial):
        raise CPNError("initial_exceeds_bound", "$.max_tokens_per_place",
                       "initial marking exceeds the analysis token bound")
    states, seen, queue = [initial], {initial: 0}, deque([0])
    edges, deadlocks, cutoffs, enabled_transitions = [], [], [], set()
    while queue:
        index = queue.popleft()
        marking = states[index]
        has_firing = False
        for transition in net.transitions:
            if any(marking[indexes[arc.place]] < arc.count for arc in transition.inputs):
                continue
            result = list(marking)
            for arc in transition.inputs:
                result[indexes[arc.place]] -= arc.count
            for arc in transition.outputs:
                result[indexes[arc.place]] += arc.count
            if any(place.capacity is not None and result[i] > place.capacity for i, place in enumerate(net.places)):
                continue
            has_firing = True
            enabled_transitions.add(transition.name)
            if any(value > max_tokens_per_place for value in result):
                cutoffs.append({"state": index, "transition": transition.name, "reason": "token_bound"})
                continue
            successor = tuple(result)
            if successor not in seen:
                if len(states) >= max_states:
                    cutoffs.append({"state": index, "transition": transition.name, "reason": "state_budget"})
                    continue
                seen[successor] = len(states)
                states.append(successor)
                queue.append(seen[successor])
            edges.append({"from": index, "to": seen[successor], "transition": transition.name})
        if not has_firing:
            deadlocks.append(index)
    complete = not cutoffs
    incoming = [0] * len(states)
    following = [[] for _ in states]
    for edge in edges:
        incoming[edge["to"]] += 1
        following[edge["from"]].append(edge["to"])
    pending = deque(i for i, degree in enumerate(incoming) if not degree)
    removed = 0
    while pending:
        current = pending.popleft()
        removed += 1
        for target in following[current]:
            incoming[target] -= 1
            if not incoming[target]:
                pending.append(target)
    cycle = removed != len(states)
    return {
        "schema_version": 1,
        "abstraction": "token-count-overapproximation",
        "ignored": ["token values", "guards", "authorizations", "timing", "transaction validity", "metadata constraints and evidence"],
        "bounds": {"max_states": max_states, "max_tokens_per_place": max_tokens_per_place},
        "complete": complete,
        "states": [{"id": i, "marking": dict(zip(names, marking, strict=True))}
                   for i, marking in enumerate(states)],
        "edges": edges,
        "deadlocks": deadlocks,
        "may_cycle": True if cycle else False if complete else None,
        "never_enabled": sorted({item.name for item in net.transitions} - enabled_transitions) if complete else None,
        "cutoffs": cutoffs,
    }

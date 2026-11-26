"""Canonical transaction plans and UTXO markings."""

from dataclasses import astuple, dataclass
from graphlib import TopologicalSorter
from hashlib import sha256
from itertools import product
import json

from shared.transaction import Output, Transaction


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def immutable(value):
    return tuple(map(immutable, value)) if isinstance(value, list) else value


@dataclass(frozen=True)
class Fields:
    versions: tuple[int, ...]
    locktime: int | None
    sequences: tuple[int | None, ...]

    def __post_init__(self):
        values = (*self.versions, self.locktime, *self.sequences)
        if any(value is not None and (type(value) is not int or not 0 <= value < 1 << 32) for value in values):
            raise ValueError("transaction field is not an unsigned 32-bit integer")
        if not self.versions or None in self.versions or self.versions != tuple(sorted(set(self.versions))):
            raise ValueError("expected a nonempty, ordered set of transaction versions")

    def intersect(self, other, *, left, right):
        """Combine constraints already mapped to the same physical inputs."""
        versions = tuple(sorted(set(self.versions) & set(other.versions)))
        if not versions:
            raise ValueError(f"{left} and {right}: conflicting nVersion")
        if len(self.sequences) != len(other.sequences):
            raise ValueError("field constraints must refer to the same input vector")

        def exact(a, b, field):
            if a is not None and b is not None and a != b:
                raise ValueError(f"{left} and {right}: conflicting {field} values {a} and {b}")
            return a if a is not None else b

        return Fields(versions, exact(self.locktime, other.locktime, "nLockTime"), tuple(
            exact(a, b, f"vin[{i}].nSequence")
            for i, (a, b) in enumerate(zip(self.sequences, other.sequences, strict=True))
        ))

    def check(self, tx):
        if tx.version not in self.versions:
            raise ValueError("unexpected nVersion")
        if self.locktime is not None and tx.locktime != self.locktime:
            raise ValueError("unexpected nLockTime")
        for index, sequence in enumerate(self.sequences):
            if sequence is not None and tx.inputs[index].sequence != sequence:
                raise ValueError(f"unexpected vin[{index}].nSequence")

    def waits_for_height(self, next_height):
        return bool(self.locktime and any(s is not None and s != 0xffffffff for s in self.sequences)
                    and (next_height is None or self.locktime >= next_height))


@dataclass(frozen=True)
class Place:
    kind: str
    spendable: bool


@dataclass(frozen=True)
class Transition:
    inputs: tuple[tuple[int, tuple[str, ...]], ...]
    outputs: tuple[int, ...]
    stages: tuple[str, ...]
    fields: Fields
    witnesses: tuple[tuple[str, str], ...]
    rules: tuple[int, ...]


@dataclass(frozen=True)
class Recipe:
    name: str
    # Each output is [amount or null, allowed lock digests]. Refund amounts
    # are derived from the consumed output and the fixed fee.
    outputs: tuple[tuple[int | None, tuple[str, ...]], ...] = ()
    refund_fee: int | None = None


@dataclass(frozen=True)
class Plan:
    places: tuple[Place, ...]
    transitions: tuple[Transition, ...]
    rules: tuple[tuple, ...]
    recipes: tuple[Recipe, ...]

    def __post_init__(self):
        if len(self.transitions) != len(self.recipes) or len({r.name for r in self.recipes}) != len(self.recipes):
            raise ValueError("expected a unique recipe per transition")
        produced = {}
        for row, recipe in zip(self.transitions, self.recipes, strict=True):
            inputs = tuple(place for place, _ in row.inputs)
            if len(inputs) != len(set(inputs)) or len(inputs) != len(row.fields.sequences):
                raise ValueError(f"{recipe.name}: invalid or repeated inputs")
            if any(place not in produced or not self.places[place].spendable for place in inputs):
                raise ValueError(f"{recipe.name}: input place has no spendable preceding output")
            if not row.outputs or not set(row.outputs) <= set(range(len(self.places))):
                raise ValueError(f"{recipe.name}: invalid output places")
            if len(row.outputs) != len(set(row.outputs)):
                raise ValueError(f"{recipe.name}: repeated output place")
            if recipe.outputs and len(recipe.outputs) != len(row.outputs):
                raise ValueError(f"{recipe.name}: recipe output count does not match")
            if any(not 0 <= rule < len(self.rules) for rule in row.rules):
                raise ValueError(f"{recipe.name}: unknown validation rule")
            for slot, place in enumerate(row.outputs):
                output = recipe.outputs[slot] if recipe.outputs else (None, ())
                if place in produced and (output[0] is None or not output[1] or output != produced[place]
                                          or recipe.refund_fee is not None):
                    raise ValueError(f"{recipe.name}: producers of place {place} must commit the same output contract")
                produced[place] = output
        if produced.keys() != set(range(len(self.places))):
            raise ValueError("a place has no producer")

    def encode(self):
        return canonical((1, tuple(map(astuple, self.places)), tuple(map(astuple, self.transitions)),
                          self.rules, tuple(map(astuple, self.recipes))))

    @classmethod
    def decode(cls, encoded):
        version, places, transitions, rules, recipes = json.loads(encoded)
        if version != 1:
            raise ValueError("unsupported transaction plan version")
        plan = cls(tuple(Place(*item) for item in places), tuple(
            Transition(tuple((place, tuple(roles)) for place, roles in inputs), tuple(outputs), tuple(stages),
                       Fields(tuple(fields[0]), fields[1], tuple(fields[2])),
                       tuple(map(tuple, witnesses)), tuple(refs))
            for inputs, outputs, stages, fields, witnesses, refs in transitions
        ), immutable(rules), tuple(Recipe(name, tuple((amount, tuple(locks)) for amount, locks in outputs), fee)
                                          for name, outputs, fee in recipes))
        if plan.encode() != encoded:
            raise ValueError("transaction plan is not in canonical encoding")
        return plan

    @property
    def digest(self):
        return sha256(self.encode()).hexdigest()

    def index(self, name):
        for index, recipe in enumerate(self.recipes):
            if recipe.name == name:
                return index
        raise ValueError(f"unknown transition {name!r}")

    def check_binding(self, index, tx, tokens):
        row = self.transitions[index]
        if row.inputs and len(tx.inputs) != len(row.inputs):
            raise ValueError("transaction input count does not match the plan")
        row.fields.check(tx)
        if len(tx.outputs) != len(row.outputs):
            raise ValueError("transaction output count does not match the plan")
        if row.inputs:
            if tuple(txin.outpoint() for txin in tx.inputs) != tuple(token.point for token in tokens):
                raise ValueError("transaction does not use the bound ordered prevouts")
            if tuple(token.place for token in tokens) != tuple(i for i, _ in row.inputs):
                raise ValueError("bound tokens do not occupy the required input places")
            if not self.compatible(index, tokens):
                raise ValueError("bound tokens do not have the required common source or slots")
            if sum(item.value for item in tx.outputs) > sum(token.output.value for token in tokens):
                raise ValueError("transaction outputs exceed its tracked inputs")
        elif tokens:
            raise ValueError("a deployment has no tracked inputs")
        recipe = self.recipes[index]
        for output, (amount, locks) in zip(tx.outputs, recipe.outputs):
            if recipe.refund_fee is not None:
                amount = tokens[0].output.value - recipe.refund_fee
            if amount is not None and output.value != amount:
                raise ValueError("output does not have the required amount")
            if locks and sha256(output.script).hexdigest() not in locks:
                raise ValueError("output does not have the required locking script")

    def compatible(self, index, tokens):
        if tokens and len({token.root for token in tokens}) != 1:
            return False
        for rule in self.transitions[index].rules:
            name = self.rules[rule][0]
            if name == "ordered-results-from-one-split":
                if (len(tokens) != 2 or any(len(token.parent.inputs) != 1 for token in tokens)
                        or tuple(token.parent.inputs[0].vout for token in tokens) != (0, 1)
                        or tokens[0].parent.inputs[0].txid != tokens[1].parent.inputs[0].txid):
                    return False
            if name == "ordered-siblings-from-one-deployment":
                if (len(tokens) != 2 or tuple(token.vout for token in tokens) != (0, 1)
                        or tokens[0].point[:32] != tokens[1].point[:32]):
                    return False
        return True


@dataclass(frozen=True)
class Token:
    place: int
    parent: Transaction
    vout: int
    root: bytes

    @property
    def output(self) -> Output:
        return self.parent.outputs[self.vout]

    @property
    def point(self):
        return self.parent.txid_wire() + self.vout.to_bytes(4, "little")

    @property
    def outpoint(self):
        return f"{self.parent.txid()}:{self.vout}"


@dataclass(frozen=True)
class Facts:
    authorizers: frozenset[str]
    witnesses: frozenset[str]
    next_height: int | None


def enabled(plan, marking, facts):
    """Find candidate bindings and report prerequisites still missing."""
    by_place = {}
    for token in sorted(marking.values(), key=lambda token: token.point):
        by_place.setdefault(token.place, []).append(token)
    result = {}
    for index, (row, recipe) in enumerate(zip(plan.transitions, plan.recipes, strict=True)):
        missing_places = [place for place, _ in row.inputs if place not in by_place]
        missing_roles = sorted({role for _, roles in row.inputs for role in roles} - facts.authorizers)
        missing_witnesses = sorted({name for name, _ in row.witnesses} - facts.witnesses)
        bindings = tuple(tokens for tokens in product(*(by_place.get(place, ()) for place, _ in row.inputs))
                         if plan.compatible(index, tokens)) if row.inputs else ()
        result[recipe.name] = {
            "inputs": missing_places, "authorizers": missing_roles, "witnesses": missing_witnesses,
            "height": row.fields.locktime if row.fields.waits_for_height(facts.next_height) else None,
            "source_mismatch": bool(row.inputs and not missing_places and not bindings), "bindings": bindings,
        }
    return result


def ready(row):
    return bool(row["bindings"]) and not any(row[key] for key in ("inputs", "authorizers", "witnesses", "height",
                                                                 "source_mismatch"))


def signing_requests(plan, index, draft, marking, facts):
    """Check a builder's draft before handing any requests to the signer."""
    row = plan.transitions[index]
    name = plan.recipes[index].name
    proposed = enabled(plan, marking, facts)[name]
    if not ready(proposed):
        missing = {key: value for key, value in proposed.items() if key != "bindings" and value}
        raise ValueError(f"{name}: transition is unavailable ({missing})")
    points = tuple(txin.outpoint() for txin in draft.tx.inputs)
    if len(points) != len(set(points)) or any(point not in marking for point in points):
        raise ValueError(f"{name}: draft does not use distinct live inputs")
    tokens = tuple(marking[point] for point in points)
    plan.check_binding(index, draft.tx, tokens)
    requests = draft.signing_requests()
    expected = tuple((i, owner) for i, (_, roles) in enumerate(row.inputs) for owner in roles)
    if tuple((request.input_index, request.authorizer) for request in requests) != expected:
        raise ValueError(f"{name}: signing requests do not match the input roles")
    for ref in row.rules:
        rule = plan.rules[ref]
        if rule[0] == "sighash" and any(request.sighash not in rule[1] for request in requests):
            raise ValueError(f"{name}: signing request uses a disallowed sighash")
    return requests


@dataclass(frozen=True)
class Effect:
    consumed: tuple[Token, ...]
    produced: tuple[Token, ...]


def check_effect(plan, index, tx, marking, *, validate, next_height):
    """Check actual wire fields and delegate Script and chain checks to the caller."""
    row = plan.transitions[index]
    points = tuple(txin.outpoint() for txin in tx.inputs)
    if len(points) != len(set(points)):
        raise ValueError("transaction contains a duplicate outpoint")
    if row.inputs and any(point not in marking for point in points):
        raise ValueError("missing live input in the marking")
    tokens = tuple(marking[point] for point in points) if row.inputs else ()
    plan.check_binding(index, tx, tokens)
    if row.fields.waits_for_height(next_height):
        raise ValueError("transaction is nonfinal at the supplied block height")
    if validate(tx, tokens) is not True:
        raise ValueError("transaction validation failed")
    root = tokens[0].root if tokens else tx.txid_wire()
    return Effect(tokens, tuple(Token(place, tx, slot, root) for slot, place in enumerate(row.outputs)
                                if plan.places[place].spendable))


def apply(marking, effect):
    if any(marking.get(token.point) != token for token in effect.consumed):
        raise ValueError("effect consumes an unavailable input")
    if any(token.point in marking for token in effect.produced):
        raise ValueError("effect recreates a live outpoint")
    remaining = dict(marking)
    for token in effect.consumed:
        del remaining[token.point]
    remaining.update((token.point, token) for token in effect.produced)
    return remaining


def lock_digests(*scripts):
    return tuple(sorted({sha256(bytes.fromhex(script)).hexdigest() for script in scripts if script is not None}))


def output_recipe(artifact, step, kinds):
    if step == "deploy":
        outputs = artifact.get("deployment_outputs", [artifact["deploy_output"]])
    elif kinds == ("work", "work"):
        outputs = artifact["work_outputs"]
    elif kinds == ("split-lock",):
        outputs = (artifact["gated_fork_output"],)
    elif kinds == ("result", "data"):
        outputs = (artifact["result_output"], artifact["data_output"])
    elif kinds == ("state",):
        outputs = (artifact.get("state_outputs", {}).get(step, artifact["state_output"]),)
    elif kinds and kinds[0] == "terminal":
        terminals = list(artifact["terminal_outputs"].values())
        amounts = {output["satoshis"] for output in terminals}
        pay = (next(iter(amounts)) if len(amounts) == 1 else None, lock_digests(*(t["script_hex"] for t in terminals)))
        return (pay, *((0, ()) for _ in kinds[1:]))
    else:
        return ()
    return tuple((output["satoshis"], lock_digests(output.get("script_hex"))) for output in outputs)


def from_build(artifact):
    """Lower selected 4thGraph templates to the CPN IR."""
    graph = artifact["transaction_graph"]
    if graph["schema_version"] != 1:
        raise ValueError("unsupported graph schema")
    versions = tuple(sorted(set(artifact["supported_transaction_versions"])))
    families = artifact.get("sighash_families")
    sighashes = (row["flag"] for row in families.values()) if families else (artifact.get("sighash"),)
    allowed = tuple(sorted({int(flag, 16) for flag in sighashes if flag is not None}))
    places, ids, transitions, rules, recipes = [], {}, [], [], []

    def append(name, inputs, outputs, stages, fields, witnesses, checks, recipe):
        destinations = []
        for item in outputs:
            key = name, item["vout"]
            if key in ids or item["vout"] != len(destinations):
                raise ValueError(f"{name}: output slots must be unique and ordered")
            ids[key] = len(places)
            destinations.append(len(places))
            places.append(Place(item["kind"], item["spendable"]))
        for check in checks:
            if check not in rules:
                rules.append(check)
        transitions.append(Transition(inputs, tuple(destinations), tuple(stages), fields, witnesses,
                                      tuple(rules.index(check) for check in checks)))
        recipes.append(recipe)

    normal = {item["step"]: item for item in graph["transactions"]}
    if len(normal) != len(graph["transactions"]):
        raise ValueError("duplicate transaction template")
    topology = TopologicalSorter({name: {src["from"]["step"] for src in item["inputs"]}
                                  for name, item in normal.items()})
    topology.prepare()
    order = []
    while topology.is_active():
        ready = sorted(topology.get_ready())
        order.extend(ready)
        topology.done(*ready)
    for name in order:
        item = normal[name]
        inputs = tuple((ids[(src["from"]["step"], src["from"]["vout"])], tuple(src["authorizers"]))
                       for src in item["inputs"])
        fields = Fields(versions, None, (None,) * len(inputs))
        outputs = output_recipe(artifact, name, tuple(row["kind"] for row in item["outputs"]))
        checks = tuple((guard,) for guard in item.get("guards", ()))
        if allowed and any(roles for _, roles in inputs):
            checks += (("sighash", allowed),)
        append(name, inputs, item["outputs"], item["executes"], fields,
               tuple((name, "u32") for name in item["external_inputs"]),
               checks, Recipe(name, outputs))

    recovery = artifact.get("recovery")
    for item in sorted(graph["refunds"], key=lambda refund: refund["step"]):
        name, ref = item["step"], item["from"]
        fields = Fields(versions, item["locktime"], (recovery["sequence"],))
        inputs = ((ids[(ref["step"], ref["vout"])], (item["authorizer"],)),)
        recipe = Recipe(name, ((None, lock_digests(recovery.get("destination_script_hex"))),), recovery.get("fee_satoshis"))
        append(name, inputs, (item["output"],), (), fields, (),
               (("actual-prevouts",), ("actual-successors",), ("input-authorizations",), ("sighash", (0x41,))), recipe)
    return Plan(tuple(places), tuple(transitions), tuple(rules), tuple(recipes))


def mermaid(plan):
    lines = ["flowchart LR"]
    for index, (row, recipe) in enumerate(zip(plan.transitions, plan.recipes, strict=True)):
        title = recipe.name
        if row.fields.locktime is not None:
            title += f" · locktime {row.fields.locktime}"
        lines.append(f'    T{index}["{title}"]')
        for place, roles in row.inputs:
            label = f'|{", ".join(roles)}|' if roles else ""
            lines.append(f"    P{place} -->{label} T{index}")
        for slot, place in enumerate(row.outputs):
            label = f"{recipe.name}:{slot} · {plan.places[place].kind}"
            lines.append(f'    T{index} --> P{place}(("{label}"))')
    return "\n".join(lines)

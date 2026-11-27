"""Opt-in, finite source-IR transformations. The ScriptBuilder release path is unchanged."""

from dataclasses import asdict, replace

from .ranges import Slot, primitive_outputs, remainder_is_identity
from .script_formula import ARITHMETIC, GENESIS_NUM_BYTES, Formula, Step, magnitude_bits
from .wordsets import PRIMITIVES

RULES = ("double-as-add", "common-values", "fold-literals", "factor-products", "elide-redundant-remainder")
MAX_DEPTH = 3


def validate_rules(rules):
    if not isinstance(rules, (list, tuple)) or len(rules) > MAX_DEPTH or any(name not in RULES for name in rules):
        raise ValueError(f"expected up to {MAX_DEPTH} semantic rules from {RULES}")
    return tuple(rules)


def snapshot(formula):
    uses = [[] for _ in formula.steps]
    for i, step in enumerate(formula.steps):
        for arg in step.args:
            uses[arg].append(i)
    for result in formula.returns:
        uses[result].append(len(formula.steps))
    return {"inputs": formula.input_count, "returns": formula.returns, "steps": [
        {"id": i, "op": step.operation, "args": step.args, "immediate": step.immediate,
         "bounds": step.bounds.bounds, "basis": ("caller-precondition" if step.operation in ("input", "int-from-bottom")
                                               else "literal" if step.operation == "literal" else "interval-propagation"),
         "uses": uses[i], "last_use_in_source_order": max(uses[i], default=None),
         "origins": [asdict(loc) for loc in origin]}
        for i, (step, origin) in enumerate(zip(formula.steps, formula.origins, strict=True))]}


def factored_product(step, steps):
    if step.operation not in {"int+", "int-"}:
        return None
    left, right = (steps[index] for index in step.args)
    if left.operation != "int*" or right.operation != "int*":
        return None
    for factor, a in (left.args, left.args[::-1]):
        for shared, b in (right.args, right.args[::-1]):
            if factor != shared:
                continue
            combined_bounds, = primitive_outputs(PRIMITIVES[step.operation], (steps[a].bounds, steps[b].bounds))
            combined = Step(step.operation, combined_bounds, (a, b))
            if magnitude_bits((combined,)) >= GENESIS_NUM_BYTES * 8:
                continue
            product_bounds, = primitive_outputs(PRIMITIVES["int*"], (steps[factor].bounds, combined_bounds))
            product = Step("int*", product_bounds, (factor, len(steps)))
            if magnitude_bits((product,)) < GENESIS_NUM_BYTES * 8:
                # The original result interval also holds for the equivalent product.
                return combined, replace(product, bounds=step.bounds)
    return None


def redundant_remainder(step, steps):
    if step.operation != "int-rem":
        return False
    value, divisor = step.args
    left, right = steps[value], steps[divisor]
    if right.bounds.bounds is None or right.bounds.bounds[0] <= 0:
        return False
    # Two signed remainders by the same positive divisor are idempotent,
    # including a negative first remainder and divisors wider than a cell.
    return ((left.operation == "int-rem" and left.args[1] == divisor)
            or remainder_is_identity((left.bounds, right.bounds)))


def transform(formula, rule, *, diagnostics=None):
    if rule not in RULES:
        raise ValueError(f"unknown semantic rule {rule!r}")
    if any(step.operation not in ARITHMETIC | {"literal", "input"} for step in formula.steps):
        raise ValueError("ordered experiments require a closed straight-line arithmetic formula")
    steps, origins, ids, common = [], [], [], {}
    applications = 0
    for i, step in enumerate(formula.steps):
        args = tuple(ids[arg] for arg in step.args)
        step = replace(step, args=args)
        origin = formula.origins[i]
        if rule == "double-as-add" and step.operation == "int*":
            for constant, value in (args, args[::-1]):
                if steps[constant].operation == "literal" and steps[constant].immediate == 2:
                    # For canonical bounded ScriptNum, x+x and 2*x have identical bounds and encoding.
                    step = replace(step, operation="int+", args=(value, value))
                    applications += 1
                    break
        elif rule == "fold-literals" and args and all(steps[arg].operation == "literal" for arg in args):
            value, = PRIMITIVES[step.operation].run(*(steps[arg].immediate for arg in args))
            origin = tuple(dict.fromkeys((*origin, *(loc for arg in args for loc in origins[arg]))))
            step = Step("literal", Slot("script-int", (value, value)), immediate=value)
            applications += 1
        elif rule == "factor-products":
            factored = factored_product(step, steps)
            if factored is not None:
                combined, step = factored
                origin = tuple(dict.fromkeys((*origin, *(loc for arg in args for loc in origins[arg]))))
                steps.append(combined)
                origins.append(origin)
                applications += 1
        elif rule == "elide-redundant-remainder" and redundant_remainder(step, steps):
            value, divisor = args
            origins[value] = tuple(dict.fromkeys((*origins[value], *origin, *origins[divisor])))
            ids.append(value)
            applications += 1
            continue
        if rule == "common-values" and step.operation != "input" and step in common:
            dest = common[step]
            origins[dest] = tuple(dict.fromkeys((*origins[dest], *origin)))
            applications += 1
        else:
            dest = len(steps)
            common[step] = dest
            steps.append(step)
            origins.append(origin)
        ids.append(dest)
    if diagnostics is not None:
        diagnostics.append({"rule": rule, "applications": applications})
    return Formula(formula.input_count, tuple(steps), tuple(ids[i] for i in formula.returns), tuple(origins))


def enumerate_orders(formula, depth=MAX_DEPTH):
    """Breadth first; all states here have the same fixture, facts, allowed suffix and terminal."""
    if type(depth) is not int or not 0 <= depth <= MAX_DEPTH:
        raise ValueError("invalid ordered search depth")
    queue = [((), formula)]
    seen = {(formula, formula.origins, depth)}
    for plan, state in queue:
        yield plan
        if len(plan) == depth:
            continue
        for rule in RULES:
            candidate = transform(state, rule)
            if (candidate, candidate.origins) == (state, state.origins):
                continue
            key = candidate, candidate.origins, depth-len(plan)-1
            if key not in seen:
                seen.add(key)
                queue.append((plan+(rule,), candidate))

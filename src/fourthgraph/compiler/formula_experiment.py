"""Opt-in, finite source-IR transformations. The ScriptBuilder release path is unchanged."""

from dataclasses import asdict, replace

from .script_formula import ARITHMETIC, Formula

RULES = ("double-as-add", "common-values")
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


def transform(formula, rule):
    if rule not in RULES:
        raise ValueError(f"unknown semantic rule {rule!r}")
    if any(step.operation not in ARITHMETIC | {"literal", "input"} for step in formula.steps):
        raise ValueError("ordered experiments require a closed straight-line arithmetic formula")
    steps, origins, ids, common = [], [], [], {}
    for i, step in enumerate(formula.steps):
        args = tuple(ids[arg] for arg in step.args)
        step = replace(step, args=args)
        if rule == "double-as-add" and step.operation == "int*":
            for constant, value in (args, args[::-1]):
                if steps[constant].operation == "literal" and steps[constant].immediate == 2:
                    # For canonical bounded ScriptNum, x+x and 2*x have identical bounds and encoding.
                    step = replace(step, operation="int+", args=(value, value))
                    break
        if rule == "common-values" and step.operation != "input" and step in common:
            dest = common[step]
            origins[dest] = tuple(dict.fromkeys((*origins[dest], *formula.origins[i])))
        else:
            dest = len(steps)
            common[step] = dest
            steps.append(step)
            origins.append(formula.origins[i])
        ids.append(dest)
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

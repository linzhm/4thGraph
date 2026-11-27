"""Lower the executable linear subset of a typed logical CPN to a workflow."""

import re

from fourthgraph.compiler.lowering import OPTIMIZATIONS, compile_word
from fourthgraph.compiler.source import CompileError, SourceCompiler, expanded
from fourthgraph.workflow.logical_cpn import CPNError, parse_net

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")


def _identifier(value, path):
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise CPNError("unsupported_identifier", path, "expected an ASCII Forth identifier")
    return value


def _metadata(metadata, path, *, place):
    supported = {"visibility"} if place else {"authorization", "constraints", "evidence", "witnesses"}
    for key, value in metadata.items():
        if key not in supported and value not in (None, [], {}):
            raise CPNError("unsupported_requirement", path + "." + key,
                           "this requirement has no executable lowering")
        if key == "visibility" and value != "public":
            raise CPNError("unsupported_requirement", path + ".visibility",
                           "this lowering requires public state")
    if place:
        return None
    authorization = metadata.get("authorization")
    if not isinstance(authorization, list) or len(authorization) != 1 or not isinstance(authorization[0], str):
        raise CPNError("unsupported_authorization", path + ".authorization",
                       "each transition requires exactly one role name")
    return _identifier(authorization[0], path + ".authorization[0]")


def _evidence(transition, path, *, terminal):
    metadata = transition.metadata
    witnesses = metadata.get("witnesses", [])
    if witnesses and not terminal:
        raise CPNError("unsupported_witness", path + ".witnesses",
                       "only the terminal transition supports witness operands")
    result, names = [], set()
    for i, witness in enumerate(witnesses):
        location = f"{path}.witnesses[{i}]"
        if not isinstance(witness, dict) or set(witness) != {"name", "type", "visibility"}:
            raise CPNError("unsupported_witness", location, "expected name, type and visibility")
        name = _identifier(witness["name"], location + ".name")
        if name.casefold() in names:
            raise CPNError("duplicate_identifier", location + ".name", "witness names must be unique ignoring case")
        names.add(name.casefold())
        if witness["type"] != "u32" or witness["visibility"] not in ("public", "private"):
            raise CPNError("unsupported_witness", location, "expected a public or private u32 witness")
        kind = "private-witness:" if witness["visibility"] == "private" else "witness:"
        result.append(f"{kind} {transition.name} {name} u32 ;\n")
    evidence = metadata.get("evidence", [])
    if evidence:
        if (len(evidence) != 1 or not isinstance(evidence[0], dict)
                or set(evidence[0]) - {"policy", "assignment_disclosure"} or "policy" not in evidence[0]):
            raise CPNError("unsupported_evidence", path + ".evidence",
                           "expected a single evidence policy and optional assignment disclosure")
        policy = evidence[0]["policy"]
        if policy not in ("allow-direct", "require-proof", "require-zk"):
            raise CPNError("unsupported_evidence", path + ".evidence[0].policy", "unknown evidence policy")
        result.append(f"policy: {transition.name} {policy} ;\n")
        if "assignment_disclosure" in evidence[0]:
            if evidence[0]["assignment_disclosure"] != "allow" or policy == "require-zk":
                raise CPNError("unsupported_evidence", path + ".evidence[0].assignment_disclosure",
                               "assignment disclosure must be allow and compatible with the policy")
            result.append(f"assignment-disclosure: {transition.name} allow ;\n")
    return "".join(result)


def _constraints(transition, stage, frontend, path):
    constraints = transition.metadata.get("constraints", [])
    if not constraints:
        return
    if len(constraints) != 1 or not isinstance(constraints[0], dict) or set(constraints[0]) != {
            "kind", "operand", "range"} or constraints[0]["kind"] != "range":
        raise CPNError("unsupported_constraint", path, "expected one structured range constraint")
    operand = _identifier(constraints[0]["operand"], path + "[0].operand").casefold()
    range_name = _identifier(constraints[0]["range"], path + "[0].range").casefold()
    names = [transition.inputs[0].name.casefold(), *(name.name for name, _ in stage.witnesses)]
    if len(names) != len(set(names)):
        raise CPNError("unsupported_constraint", path, "input and witness names must be distinct")
    if operand != names[-1]:
        raise CPNError("unsupported_constraint", path + "[0].operand", "range must apply to the entry stack top")
    bounds = frontend.ranges.get(range_name)
    if bounds is None or bounds.base != "u32" or not 0 <= bounds.lower < bounds.upper <= 1 << 32:
        raise CPNError("unsupported_constraint", path + "[0].range", "expected a declared u32 range")
    first = next(expanded(stage.word.body), None)
    if first is None:
        raise CPNError("unsupported_constraint", path, "the transition word has no range check")
    check, source = first
    if (source is None or source.name != "check-range" or check.takes != ("u32",)
            or check.gives != ("u32",) or check.checked_bounds != (bounds.lower, bounds.upper - 1)):
        raise CPNError("unsupported_constraint", path, "transition must begin with the matching check-range")
    for optimization in OPTIMIZATIONS:
        if check.code not in compile_word(stage.word, optimization).script:
            raise CPNError("unsupported_constraint", path, f"range check is absent under {optimization}")
    if stage.policy != "allow-direct" or stage.witnesses:
        from fourthgraph.verification.circuit_backend import emit_stage_circuit

        try:
            emit_stage_circuit(stage)
        except CompileError as error:
            raise CPNError("unsupported_constraint", path, f"proof circuit cannot lower the check: {error}") from error


def lower_linear(document, source, *, source_path=None):
    """Return a validated workflow frontend and its generated Forth source.

    All graph constraints must fit the supported linear public-state layout.
    The caller must retain the generated source and imports with the build.
    """
    net = parse_net(document)
    places = {place.name: place for place in net.places}
    if len(net.transitions) < 2:
        raise CPNError("unsupported_graph", "$.transitions", "at least two transitions are required")
    if any(place.capacity != 1 or place.initial > 1 for place in net.places):
        raise CPNError("unsupported_marking", "$.places", "every place requires an explicit capacity of one")
    roots = [place for place in net.places if place.initial]
    if len(roots) != 1:
        raise CPNError("unsupported_marking", "$.places", "exactly one initial state token is required")
    for i, place in enumerate(net.places):
        _identifier(place.name, f"$.places[{i}].name")
        _metadata(place.metadata, f"$.places[{i}].metadata", place=True)
        if place.type not in ("u32", "route"):
            raise CPNError("unsupported_type", f"$.places[{i}].type", "expected u32 or route")
    if len({place.name.casefold() for place in net.places}) != len(net.places):
        raise CPNError("duplicate_identifier", "$.places", "place names must be unique ignoring case")
    if len({item.name.casefold() for item in net.transitions}) != len(net.transitions):
        raise CPNError("duplicate_identifier", "$.transitions", "transition names must be unique ignoring case")

    following, producers, roles, positions = {}, {}, {}, {}
    for i, transition in enumerate(net.transitions):
        path = f"$.transitions[{i}]"
        _identifier(transition.name, path + ".name")
        _identifier(transition.word, path + ".word")
        roles[transition.name] = _metadata(transition.metadata, path + ".metadata", place=False)
        positions[transition.name] = path
        if len(transition.inputs) != 1 or len(transition.outputs) != 1:
            raise CPNError("unsupported_ports", path, "this lowering requires one input and one output port")
        incoming, outgoing = transition.inputs[0], transition.outputs[0]
        if incoming.count != 1 or outgoing.count != 1:
            raise CPNError("unsupported_multiplicity", path, "this lowering requires one token on each port")
        if incoming.place in following or outgoing.place in producers:
            raise CPNError("unsupported_branch", path, "this lowering requires a single producer and consumer per place")
        following[incoming.place] = transition
        producers[outgoing.place] = transition

    root = roots[0]
    if root.type != "u32" or root.name in producers:
        raise CPNError("unsupported_graph", "$.places", "the initial place must be a u32 without a producer")
    ordered, visited = [], {root.name}
    cursor = root.name
    while cursor in following:
        transition = following[cursor]
        destination = transition.outputs[0].place
        if destination in visited:
            raise CPNError("unsupported_cycle", "$.transitions", "cyclic CPNs require a continuation lowering")
        ordered.append(transition)
        visited.add(destination)
        cursor = destination
    if len(ordered) != len(net.transitions) or len(visited) != len(places):
        raise CPNError("unsupported_graph", "$.transitions", "all places and transitions must form one connected chain")
    for transition in ordered[:-1]:
        if places[transition.outputs[0].place].type != "u32":
            raise CPNError("unsupported_type", "$.places", "intermediate places must have u32 type")
    if places[cursor].type != "route":
        raise CPNError("unsupported_type", "$.places", "the final place must have route type")

    try:
        frontend = SourceCompiler(source, source_path=source_path)
        if (frontend.workflow_input is not None or frontend.stages or frontend.work or frontend.join or
                frontend.operator or frontend.gate or frontend.relation or frontend.recovery or frontend.independent or
                frontend.stage_verification_declared or frontend.recursions):
            raise CPNError("unsupported_source", "$.source",
                           "the Forth source must not contain transaction declarations")
        generated = source + "\nworkflow-input: " + root.name + " u32 ;\n"
        generated += "".join(
            f"stage: {item.name} {item.word} {item.inputs[0].place} {item.outputs[0].place} {roles[item.name]} ;\n"
            for item in ordered
        )
        generated += "".join(_evidence(item, positions[item.name] + ".metadata", terminal=item is ordered[-1])
                             for item in ordered)
        lowered = SourceCompiler(generated, source_path=source_path)
        workflow = lowered.workflow()
        for transition, stage in zip(ordered, workflow.stages, strict=True):
            _constraints(transition, stage, lowered, positions[transition.name] + ".metadata.constraints")
    except CompileError as error:
        raise CPNError("source_type_error", "$.source", str(error)) from error
    return lowered, generated

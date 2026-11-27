"""Lower linear CPN state chains and a terminal external witness to a workflow."""

import re

from fourthgraph.compiler.lowering import OPTIMIZATIONS, compile_word
from fourthgraph.compiler.source import CompileError, SourceCompiler, expanded
from fourthgraph.workflow.logical_cpn import CPNError, parse_net

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")


def _identifier(value, path):
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise CPNError("unsupported_identifier", path, "expected an ASCII Forth identifier")
    return value


def _metadata(metadata, path, *, place, external_witness=False):
    supported = ({"carrier", "visibility"} if external_witness else {"visibility"}) if place else {
        "authorization", "constraints", "evidence", "witnesses", "atomic_with", "independent_submit"
    }
    for key, value in metadata.items():
        if key not in supported and value not in (None, [], {}):
            raise CPNError("unsupported_requirement", path + "." + key,
                           "this requirement has no executable lowering")
        if key == "visibility" and not external_witness and value != "public":
            raise CPNError("unsupported_requirement", path + ".visibility",
                           "this lowering requires public state")
    if place:
        if external_witness and (metadata.get("carrier") != "external-witness"
                                 or metadata.get("visibility") not in ("public", "private")):
            raise CPNError("unsupported_witness", path, "external witness needs an explicit public or private visibility")
        return None
    authorization = metadata.get("authorization")
    if not isinstance(authorization, list) or len(authorization) != 1 or not isinstance(authorization[0], str):
        raise CPNError("unsupported_authorization", path + ".authorization",
                       "each transition requires exactly one role name")
    return _identifier(authorization[0], path + ".authorization[0]")


def _transaction_requirements(transitions, positions):
    """Preserve logical transaction grouping as existing workflow directives."""
    by_name = {transition.name.casefold(): transition.name for transition in transitions}
    pairs, independent = set(), []
    for transition in transitions:
        path = positions[transition.name] + ".metadata"
        metadata = transition.metadata
        atomic = metadata.get("atomic_with", [])
        if not isinstance(atomic, list):
            raise CPNError("unsupported_atomicity", path + ".atomic_with", "expected an array of transition names")
        for index, reference in enumerate(atomic):
            location = f"{path}.atomic_with[{index}]"
            name = _identifier(reference, location).casefold()
            if name not in by_name:
                raise CPNError("unsupported_atomicity", location, "unknown transition")
            if name == transition.name.casefold():
                raise CPNError("unsupported_atomicity", location, "a transition cannot be atomic with itself")
            pairs.add(tuple(sorted((transition.name.casefold(), name))))
        separate = metadata.get("independent_submit", False)
        if type(separate) is not bool:
            raise CPNError("unsupported_independence", path + ".independent_submit", "expected a boolean")
        if separate:
            independent.append(transition.name)
    result = "".join(f"atomic: {by_name[first]} {by_name[second]} ;\n" for first, second in sorted(pairs))
    return result + "".join(f"independent-submit: {name} ;\n" for name in independent)


def _evidence(transition, path, *, terminal, port_witness=None):
    metadata = transition.metadata
    witnesses = metadata.get("witnesses", [])
    if port_witness is not None:
        if witnesses:
            raise CPNError("unsupported_witness", path + ".witnesses",
                           "use either an external witness input or witness metadata, not both")
        witnesses = [port_witness]
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

    The state chain is public; one terminal input may carry an external witness.
    The caller must retain the generated source and imports with the build.
    """
    net = parse_net(document)
    places = {place.name: place for place in net.places}
    if len(net.transitions) < 2:
        raise CPNError("unsupported_graph", "$.transitions", "at least two transitions are required")
    if any(place.capacity != 1 or place.initial > 1 for place in net.places):
        raise CPNError("unsupported_marking", "$.places", "every place requires an explicit capacity of one")
    external = {place.name: place for place in net.places
                if place.metadata.get("carrier") == "external-witness"}
    roots = [place for place in net.places if place.initial and place.name not in external]
    if len(roots) != 1:
        raise CPNError("unsupported_marking", "$.places", "exactly one initial state token is required")
    for i, place in enumerate(net.places):
        _identifier(place.name, f"$.places[{i}].name")
        is_external = place.name in external
        _metadata(place.metadata, f"$.places[{i}].metadata", place=True, external_witness=is_external)
        if is_external and (place.type != "u32" or place.initial != 1):
            raise CPNError("unsupported_witness", f"$.places[{i}]",
                           "an external witness must be an initially available u32")
        if place.type not in ("u32", "route"):
            raise CPNError("unsupported_type", f"$.places[{i}].type", "expected u32 or route")
    if len({place.name.casefold() for place in net.places}) != len(net.places):
        raise CPNError("duplicate_identifier", "$.places", "place names must be unique ignoring case")
    if len({item.name.casefold() for item in net.transitions}) != len(net.transitions):
        raise CPNError("duplicate_identifier", "$.transitions", "transition names must be unique ignoring case")

    following, producers, roles, positions, external_consumers = {}, {}, {}, {}, {}
    for i, transition in enumerate(net.transitions):
        path = f"$.transitions[{i}]"
        _identifier(transition.name, path + ".name")
        _identifier(transition.word, path + ".word")
        roles[transition.name] = _metadata(transition.metadata, path + ".metadata", place=False)
        positions[transition.name] = path
        if not 1 <= len(transition.inputs) <= 2 or len(transition.outputs) != 1:
            raise CPNError("unsupported_ports", path, "this lowering requires one input and one output port, optionally with one external witness input")
        incoming, outgoing = transition.inputs[0], transition.outputs[0]
        if incoming.place in external or outgoing.place in external:
            raise CPNError("unsupported_witness", path, "external witnesses cannot carry the workflow state")
        if any(arc.count != 1 for arc in (*transition.inputs, outgoing)):
            raise CPNError("unsupported_multiplicity", path, "this lowering requires one token on each port")
        if len(transition.inputs) == 2:
            witness = transition.inputs[1]
            if witness.place not in external:
                raise CPNError("unsupported_witness", path + ".inputs[1]", "second input must be an external witness")
            _identifier(witness.name, path + ".inputs[1].name")
            if witness.name.casefold() == incoming.name.casefold():
                raise CPNError("duplicate_identifier", path + ".inputs[1].name", "input names must be distinct ignoring case")
            if witness.place in external_consumers:
                raise CPNError("unsupported_witness", path + ".inputs[1]", "external witness cannot be reused")
            external_consumers[witness.place] = transition.name
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
    if len(ordered) != len(net.transitions) or len(visited) + len(external) != len(places):
        raise CPNError("unsupported_graph", "$.transitions", "all places and transitions must form one connected chain")
    if set(external_consumers) != set(external):
        raise CPNError("unsupported_witness", "$.places", "each external witness must be consumed exactly once")
    if any(consumer != ordered[-1].name for consumer in external_consumers.values()):
        raise CPNError("unsupported_witness", "$.transitions", "only the terminal transition supports external witness inputs")
    for transition in ordered[:-1]:
        if places[transition.outputs[0].place].type != "u32":
            raise CPNError("unsupported_type", "$.places", "intermediate places must have u32 type")
    if places[cursor].type != "route":
        raise CPNError("unsupported_type", "$.places", "the final place must have route type")

    try:
        frontend = SourceCompiler(source, source_path=source_path)
        if (frontend.workflow_input is not None or frontend.stages or frontend.work or frontend.join or
                frontend.operator or frontend.gate or frontend.relation or frontend.recovery or frontend.independent or
                frontend.atomic_stages or frontend.stage_verification_declared or frontend.recursions):
            raise CPNError("unsupported_source", "$.source",
                           "the Forth source must not contain transaction declarations")
        generated = source + "\nworkflow-input: " + root.name + " u32 ;\n"
        generated += "".join(
            f"stage: {item.name} {item.word} {item.inputs[0].place} {item.outputs[0].place} {roles[item.name]} ;\n"
            for item in ordered
        )
        for item in ordered:
            port_witness = None
            if len(item.inputs) == 2:
                port = item.inputs[1]
                port_witness = {"name": port.name, "type": port.type,
                                "visibility": external[port.place].metadata["visibility"]}
            generated += _evidence(item, positions[item.name] + ".metadata", terminal=item is ordered[-1],
                                   port_witness=port_witness)
        generated += _transaction_requirements(ordered, positions)
        lowered = SourceCompiler(generated, source_path=source_path)
        workflow = lowered.workflow()
        for transition, stage in zip(ordered, workflow.stages, strict=True):
            _constraints(transition, stage, lowered, positions[transition.name] + ".metadata.constraints")
    except CompileError as error:
        raise CPNError("source_type_error", "$.source", str(error)) from error
    return lowered, generated

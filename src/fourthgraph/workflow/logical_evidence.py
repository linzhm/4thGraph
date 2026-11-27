"""Inventory logical CPN declarations without treating them as verification.

This is a structural inspection of user-supplied metadata, not a compiler,
proof verifier, transaction validator, or privacy analysis.  In particular,
a recursively named relation is not evidence that recursion is implemented.
"""

from fourthgraph.workflow.logical_cpn import parse_net


def inventory(document):
    """Describe declared state and transition requirements and obvious wiring errors.

    A transition may optionally declare ``metadata.recursion`` with input port
    names ``previous_proof`` and ``previous_state``, an output port name
    ``next_state``, and nonempty ``origin_field`` and ``base_case`` strings.
    Only the port and base-case transition references are checked.  Cryptographic relation, field
    equality, authorization, origin authenticity, and chain state are not.
    Existing free-form metadata remains valid and is not reinterpreted.
    """
    net = parse_net(document)
    diagnostics = []
    places = []
    for place in net.places:
        metadata = place.metadata
        places.append({
            "place": place.name, "type": place.type,
            "carrier": metadata.get("carrier"),
            "visibility": metadata.get("visibility"),
            "fields": metadata.get("fields"),
            "actual_outpoint": metadata.get("actual_outpoint"),
        })
    transitions = []
    transition_names = {transition.name for transition in net.transitions}
    for index, transition in enumerate(net.transitions):
        metadata = transition.metadata
        recursion = metadata.get("recursion")
        path = f"$.transitions[{index}].metadata.recursion"
        if recursion is not None:
            if not isinstance(recursion, dict):
                diagnostics.append({"code": "invalid_recursion", "path": path,
                                    "message": "expected a recursion declaration object"})
            else:
                required = {"previous_proof", "previous_state", "next_state", "origin_field", "base_case"}
                for key in sorted(required):
                    value = recursion.get(key)
                    if not isinstance(value, str) or not value.strip():
                        diagnostics.append({"code": "missing_recursion_field", "path": path + "." + key,
                                            "message": "expected a nonempty string"})
                        continue
                    ports = None
                    if key in ("previous_proof", "previous_state"):
                        ports = {arc.name for arc in transition.inputs}
                    elif key == "next_state":
                        ports = {arc.name for arc in transition.outputs}
                    if key == "base_case" and value not in transition_names:
                        diagnostics.append({"code": "unknown_recursion_base", "path": path + "." + key,
                                            "message": "base-case transition does not exist"})
                    if ports is not None and value not in ports:
                        diagnostics.append({"code": "unknown_recursion_port", "path": path + "." + key,
                                            "message": "port does not exist on the required side"})
        transitions.append({
            "transition": transition.name, "word": transition.word,
            "forth_source": metadata.get("forth_source"),
            "inputs": [arc.describe() for arc in transition.inputs],
            "outputs": [arc.describe() for arc in transition.outputs],
            "constraints": metadata.get("constraints", []),
            "authorization": metadata.get("authorization", []),
            "witnesses": metadata.get("witnesses", []),
            "evidence": metadata.get("evidence", []),
            "recursion": recursion, "recursive_requirements": metadata.get("recursive_requirements"),
            "status": "declared",
        })
    return {
        "schema_version": 1,
        "scope": "logical-declarations-only",
        "status": "declared",
        "places": places, "transitions": transitions, "diagnostics": diagnostics,
        "not_checked": ["lowering support", "constraint enforcement", "proof verification",
                        "recursive relation", "origin authentication", "transaction binding",
                        "chain state", "privacy"],
    }

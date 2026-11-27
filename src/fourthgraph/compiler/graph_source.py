"""Read and write named Forth assertion graphs for ScriptBuilder."""

from fourthgraph.bsv.script import OPS, push

from .source import named_token, required
from .stack_schedule import Graph

GRAPH_SCHEDULES = ("ordered", "compact")
OP_WORDS = {value: name.lower().replace("_", "-") for name, value in OPS.items()}
GRAPH_WORDS = {"{:", ":}", "apply", "slice", "assert", "let"}


def read_assertion_graph(tokens, entry, emit_fragment):
    """A fragment consumes the listed local operands and produces one value."""
    schedule = required(tokens, entry, "assertion graph schedule")
    if schedule.name not in GRAPH_SCHEDULES or required(tokens, entry, "'{:'").name != "{:":
        raise schedule.error("expected an assertion graph schedule and input names in '{: ... :}'")
    names = []
    for token in tokens:
        if token.name == ":}":
            break
        if token.name in names or token.name in GRAPH_WORDS or not token.name.isidentifier():
            raise token.error("invalid or repeated assertion graph input name")
        names.append(token.name)
    else:
        raise entry.error("unterminated assertion graph inputs")

    graph = Graph(len(names), share=False)
    locals_ = dict(zip(names, graph.inputs))
    checks = []
    operands = []

    def unsigned(field):
        value = required(tokens, entry, field)
        if not value.text.isascii() or not value.text.isdecimal() or len(value.text) > 10:
            raise value.error(f"{field} must be an unsigned byte offset or width")
        return int(value.text)

    for token in tokens:
        name = token.name
        if name == ";":
            if operands or not checks:
                raise token.error("assertion graph requires a check and no trailing operands")
            return graph.emit_assertions(checks, compact=True, optimize=schedule.name == "compact")
        if name in locals_:
            operands.append(locals_[name])
            continue
        if name == "assert":
            if len(operands) != 1:
                raise token.error("ASSERT requires one named value")
            checks.append(operands.pop())
            continue
        if name == "apply":
            word = named_token(tokens, token, "Script fragment word")
            result = graph.define(emit_fragment(word), operands)
        elif name == "slice":
            if len(operands) != 1:
                raise token.error("SLICE requires one named packet")
            offset, width = unsigned("slice offset"), unsigned("slice width")
            if not width:
                raise token.error("SLICE requires a positive width")
            result = graph.packet_slice(operands[0], offset, width)
        else:
            raise token.error(f"unknown assertion graph word {token.text!r}")
        if required(tokens, token, "LET").name != "let":
            raise token.error("each graph operation must be followed by LET")
        local = named_token(tokens, token, "graph local")
        if local.name in locals_ or local.name in GRAPH_WORDS:
            raise local.error("invalid or repeated assertion graph local")
        locals_[local.name] = result
        operands.clear()
    raise entry.error("unterminated assertion graph")


def fragment_forth(script):
    """Spell a Script fragment as opcode words and explicit byte literals."""
    words = []
    cursor = 0
    while cursor < len(script):
        start = cursor
        op = script[cursor]
        cursor += 1
        if 1 <= op <= 78:
            if op <= 75:
                size = op
            else:
                width = 1 << (op - 76)
                size = int.from_bytes(script[cursor:cursor + width], "little")
                cursor += width
            data = script[cursor:cursor + size]
            cursor += size
            if script[start:cursor] != push(data) or not data:
                raise ValueError("fragment contains an invalid or noncanonical byte push")
            words.extend(("bytes-hex", data.hex(), "bsv-push"))
        elif op in OP_WORDS:
            words.append(OP_WORDS[op])
        else:
            raise ValueError(f"no Forth opcode word for {op:#04x}")
    return " ".join(words)


def render_assertion_graph(graph, checks, name, *, schedule, input_names, sections=None, fragments=None):
    """Render live graph operations and assertions as reusable ScriptBuilder source."""
    if schedule not in GRAPH_SCHEDULES or len(input_names) != len(graph.inputs):
        raise ValueError("invalid assertion graph schedule or input names")
    checks = set(checks)
    names = dict(zip(graph.inputs, input_names, strict=True))
    fragments = dict(fragments or {})
    definitions = []
    body = [f"assertion-graph: {name} {schedule} {{: {' '.join(input_names)} :}}"]
    for value, node in graph.live_definitions(checks):
        if sections and value.slot in sections:
            body.extend(("", "    ( " + sections[value.slot] + " )"))
        local = f"v{value.slot}"
        operands = " ".join(names[arg] for arg in node.args)
        if operands:
            operands += " "
        read = graph.packet_reads.get(value)
        if read is not None:
            if read.decode or read.chronicle:
                raise ValueError("graph source requires plain Genesis packet slices")
            operation = f"slice {read.offset} {read.width}"
        else:
            script = node.script
            if len(script) == 1 and script[0] in OP_WORDS:
                fragment = OP_WORDS[script[0]]
            else:
                fragment = fragments.get(script)
                if fragment is None:
                    fragment = f"assert-fragment-{len(definitions)}"
                    definitions.append(f": {fragment} ( script -- script ) {fragment_forth(script)} ;")
                    fragments[script] = fragment
            operation = f"apply {fragment}"
        body.append(f"    {operands}{operation} let {local}")
        names[value] = local
        if value in checks:
            body.append(f"    {local} assert")
    body[1:1] = [f"    {name} assert" for arg, name in zip(graph.inputs, input_names) if arg in checks]
    return "\n".join((*definitions, "", *body, ";", ""))

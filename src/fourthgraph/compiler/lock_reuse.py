"""Reuse identical deterministic expressions within one lock control-flow block."""
from dataclasses import replace

from .wordsets import PRIMITIVES, Literal, Primitive


def reuse_values(block):
    """Return a rewritten block and the reasons for its replacements."""
    constants, widths, aliases, seen = {}, {}, {}, {}
    emitted, reused = [], []
    for step in block.steps:
        args = tuple(aliases.get(slot, slot) for slot in step.args)
        step = replace(step, args=args)
        node = step.node
        if isinstance(node, Literal):
            key = node
        elif isinstance(node, Primitive) and node.repeatable and not node.requires_checksig:
            if node is PRIMITIVES["bytes-check-size"]:
                bounded = args[1] in constants and constants[args[1]] >= 0
            else:
                bounded = all(slot in widths for slot, kind in zip(args, node.takes, strict=True) if kind == "bytes")
            key = (id(node), args) if bounded else None
        else:
            key = None
        if key is not None and key in seen:
            aliases.update(zip(step.results, seen[key], strict=True))
            reused.append((step, "reuse-dominating-expression", "identical operands in the same block", None))
            continue
        if key is not None:
            seen[key] = step.results
        if isinstance(node, Literal):
            result, = step.results
            if isinstance(node.value, bytes):
                widths[result] = len(node.value)
            else:
                constants[result] = node.value
        elif node is PRIMITIVES["bytes-check-size"] and key is not None:
            widths[step.results[0]] = constants[args[1]]
        elif node is PRIMITIVES["op_split"] and args[0] in widths and args[1] in constants:
            width, index = widths[args[0]], constants[args[1]]
            if 0 <= index <= width:
                widths.update(zip(step.results, (index, width - index), strict=True))
        elif node is PRIMITIVES["bytes-cat"] and key is not None:
            widths[step.results[0]] = widths[args[0]] + widths[args[1]]
        elif node is PRIMITIVES["bytes-sha256"]:
            widths[step.results[0]] = 32
        if isinstance(node, Primitive) and node.fixed_width_code is not None:
            width, code = node.fixed_width_code
            if node.takes[0] == "bytes" and widths.get(args[0]) == width and len(code) < len(node.code):
                step = replace(step, node=replace(node, code=code))
                reused.append((step, "fixed-width-replacement", f"first operand is exactly {width} bytes",
                               (len(node.code), len(code))))
        emitted.append(step)
    returns = tuple(aliases.get(slot, slot) for slot in block.returns)
    return replace(block, steps=tuple(emitted), returns=returns), reused

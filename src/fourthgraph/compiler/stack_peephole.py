"""Shorten groups of literal-depth stack operations before signing."""

from functools import lru_cache

from fourthgraph.bsv.script import asm, decode_num, number, script_operations
from fourthgraph.compiler.stack_schedule import compact_pair_moves


DROP, DROP2, OVER, DUP2, DUP3, PICK, ROLL, ROT, ROT2, SWAP, SWAP2, TUCK = map(
    asm, ("OP_DROP", "OP_2DROP", "OP_OVER", "OP_2DUP", "OP_3DUP", "OP_PICK",
          "OP_ROLL", "OP_ROT", "OP_2ROT", "OP_SWAP", "OP_2SWAP", "OP_TUCK"),
)

STATIC_REWRITES = {
    (DROP, DROP): DROP2,
    (OVER, OVER): DUP2,
    (SWAP, OVER): TUCK,
    (SWAP, ROT, SWAP): ROT + ROT,
    (number(2) + PICK, number(2) + PICK): DUP3 + DROP,
}


def _literal_depth(operation):
    if operation == b"\x00":
        return 0
    if len(operation) == 1 and 0x51 <= operation[0] <= 0x60:
        return operation[0] - 0x50
    # Leave room for depth + 1 in the original four-byte Script number limit.
    if 2 <= len(operation) <= 4 and operation[0] == len(operation) - 1:
        depth = decode_num(operation[1:])
        if depth >= 0 and operation == number(depth):
            return depth
    return None


def _instructions(script):
    pending = None
    for operation in script_operations(script):
        if pending is not None:
            if operation in (PICK, ROLL) and _literal_depth(pending) is not None:
                yield pending + operation
                pending = None
                continue
            yield pending
        pending = operation
    if pending is not None:
        yield pending


def _roll_depth(operation):
    if operation == ROT:
        return 2
    if operation == SWAP:
        return 1
    return _literal_depth(operation[:-1]) if operation.endswith(ROLL) else None


def _roll(depth):
    return (b"", SWAP, ROT)[depth] if depth < 3 else number(depth) + ROLL


def _rewrite(window):
    if window in STATIC_REWRITES:
        return STATIC_REWRITES[window]
    if len(window) == 3:
        first, middle, last = window
        if first == last == DROP and (depth := _roll_depth(middle)) is not None:
            # Delay the first drop and reach one slot deeper for the second.
            return _roll(depth + 1) + DROP2
        if (middle, last) == (ROT, SWAP) and (depth := _roll_depth(first)) is not None and depth >= 2:
            # Swap the original top two items before pulling the deeper one up.
            return SWAP + _roll(depth)
    if len(window) == 4:
        first, second, third, last = window
        if second == last == DROP and (left := _roll_depth(first)) is not None:
            right = _roll_depth(third)
            if right is not None:
                if (left, right) == (3, 2):
                    return SWAP2 + DROP2
                if (left, right) == (5, 4):
                    return ROT2 + DROP2
                return _roll(left) + _roll(right + 1) + DROP2
        # Three pair rotations restore the stack if six items are available.
        # An adjacent literal PICK can establish that minimum depth.
        if window[1:] == (ROT2,) * 3 and first.endswith(PICK):
            depth = _literal_depth(first[:-1])
            if depth is not None and depth >= 4:
                return first
        if window[:3] == (ROT2,) * 3 and last.endswith(PICK):
            depth = _literal_depth(last[:-1])
            if depth is not None and depth >= 5:
                return last
    return None


def compact_stack_moves(script):
    """Select shorter equivalent stack windows in unsigned compiler output.

    Each replacement has the same final stack and minimum input depth.
    Callers must account for temporary stack growth, including one extra copy
    when a pair of picks becomes OP_3DUP OP_DROP.
    """
    instructions = tuple(_instructions(compact_pair_moves(script)))
    rewrite = lru_cache(maxsize=4096)(_rewrite)
    sizes = [0] * (len(instructions) + 1)
    choices = [None] * len(instructions)
    # Evaluate overlapping windows against the shortest remaining suffix.
    for index in range(len(instructions) - 1, -1, -1):
        operation = instructions[index]
        best = len(operation) + sizes[index + 1]
        for width in range(2, min(4, len(instructions) - index) + 1):
            replacement = rewrite(instructions[index:index + width])
            if replacement is not None and len(replacement) + sizes[index + width] < best:
                best = len(replacement) + sizes[index + width]
                choices[index] = width, replacement
        sizes[index] = best

    output = bytearray()
    index = 0
    while index < len(instructions):
        width, replacement = choices[index] or (1, instructions[index])
        output.extend(replacement)
        index += width
    return bytes(output)

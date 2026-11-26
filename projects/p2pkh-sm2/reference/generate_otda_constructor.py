"""Rebuild the frozen OTDA constructor for the published v1.0.0 lock."""
import argparse
from collections import defaultdict
from pathlib import Path

from assemble import sm3_blocks
from p2pkh_sm2 import _canonical
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, assemble, number, push

ASM_DIRECTORY = Path(__file__).with_name("asm")

# (SM3 function, emitted instance, byte offset, width). These ranges
# parameterize the shared instruction sequences extracted by the SM3 emitter.
SM3_FRAGMENTS = (
    ("message_expansion", 0, 60, 19),
    ("data_round_late", 0, 101, 40),
    ("padding_round_late", 0, 100, 34),
    ("padding_round_late", 0, 27, 67),
    ("data_round_late", 0, 27, 68),
    ("message_expansion", 0, 23, 13),
    ("data_round_early", 1, 91, 35),
    ("data_round_early", 1, 27, 58),
)


def function_library():
    fragments = {}
    sm3_blocks(fragments=fragments)
    library = []
    for name, instance, offset, width in SM3_FRAGMENTS:
        fragment = fragments[name][instance][offset:offset + width]
        if len(fragment) != width:
            raise ValueError(f"SM3 constructor fragment changed: {name}")
        library.append(fragment)
    for name in ("DOUBLE_POINT", "ADD_POINTS"):
        library.append(assemble(ASM_DIRECTORY, bytes(20), entry=name))
    return library


def match_length(raw, source, target, lower, upper):
    """Find the common prefix of two spans whose first lower bytes agree."""
    while lower < upper:
        size = (lower + upper + 1) // 2
        if raw[source:source + size] == raw[target:target + size]:
            lower = size
        else:
            upper = size - 1
    return lower


def copy_span(offset, width, accumulator_size):
    program = asm("OP_DUP")
    if offset:
        program += number(offset) + asm("OP_SPLIT OP_NIP")
    if offset + width < accumulator_size:
        program += number(width) + asm("OP_SPLIT OP_DROP")
    return program


def keep_shorter(options, length, program):
    prior = options.get(length)
    if prior is None or len(program) < len(prior):
        options[length] = program


def earlier_spans(raw, options):
    seed_width = 11
    earlier = defaultdict(list)
    cat = asm("OP_CAT")
    double = asm("OP_DUP OP_CAT")
    for cursor in range(len(raw) - seed_width + 1):
        key = raw[cursor:cursor + seed_width]
        matches = earlier[key]
        for offset in sorted(set(matches[:2] + matches[-4:])):
            gap = cursor - offset
            remaining = len(raw) - cursor
            if gap < seed_width:
                continue
            width = match_length(raw, offset, cursor, seed_width, min(gap, remaining))
            source = copy_span(offset, width, cursor)
            keep_shorter(options[cursor], width, source + cat)
            if width != gap or 2 * gap > remaining:
                continue
            count = match_length(raw, offset, cursor, width, remaining) // gap
            # Reproduce long contiguous runs, including the curve's window
            # blocks, by copying one fragment and doubling it repeatedly.
            repeat = 2
            while repeat <= count:
                keep_shorter(options[cursor], repeat * gap, source + double * (repeat.bit_length() - 1) + cat)
                repeat *= 2
        matches.append(cursor)


def compile_suffix(raw, library):
    """Encode the suffix as literal runs, cached functions and earlier spans."""
    cat = asm("OP_CAT")
    options = [{} for _ in raw]
    earlier_spans(raw, options)
    for index, fragment in enumerate(library):
        depth = len(library) - index
        copy = asm("OP_OVER") if depth == 1 else number(depth) + asm("OP_PICK")
        position = raw.find(fragment)
        while position != -1:
            keep_shorter(options[position], len(fragment), copy + cat)
            position = raw.find(fragment, position + 1)
    # Score unframed literal bytes here, then serialize contiguous literals
    # as a single push. The release fixture pins the resulting exact bytes.
    costs = [0] * (len(raw) + 1)
    choices = [None] * len(raw)
    for cursor in range(len(raw) - 1, -1, -1):
        costs[cursor] = 1 + costs[cursor + 1]
        for width, code in options[cursor].items():
            cost = len(code) + costs[cursor + width]
            if cost < costs[cursor]:
                costs[cursor] = cost
                choices[cursor] = width, code

    program = bytearray(b"".join(map(push, library)) + asm("OP_0"))
    cursor = 0
    while cursor < len(raw):
        start = cursor
        while cursor < len(raw) and choices[cursor] is None:
            cursor += 1
        if cursor != start:
            program.extend(push(raw[start:cursor]) + cat)
        if cursor < len(raw):
            width, code = choices[cursor]
            program.extend(code)
            cursor += width
    program.extend(asm("OP_TOALTSTACK") + asm("OP_2DROP") * (len(library) // 2))
    program.extend(asm("OP_DROP") * (len(library) % 2) + asm("OP_FROMALTSTACK"))
    return bytes(program)


def generate():
    lock, offset = _canonical()
    prefix, suffix = lock[:offset], lock[offset + 20:]
    program = push(prefix) + compile_suffix(suffix, function_library())
    if evaluate(program) != ([prefix, suffix], []):
        raise ValueError("OTDA constructor does not reproduce the canonical SM2 template")
    return program


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination for the hexadecimal constructor")
    parser.parse_args().output.write_text(generate().hex() + "\n", encoding="ascii")

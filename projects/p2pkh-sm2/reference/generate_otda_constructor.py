"""Rebuild the frozen OTDA constructor for a canonical P2PKH-SM2 lock."""
import argparse
from collections import Counter, defaultdict
from pathlib import Path

from assemble import TEMPLATE_VERSION, TEMPLATE_VERSIONS, forth_compiler, sm3_blocks
from p2pkh_sm2 import _canonical
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, number, push

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


def function_library(version=TEMPLATE_VERSION):
    fragments = {}
    sm3_blocks(version=version, fragments=fragments)
    library = []
    for name, instance, offset, width in SM3_FRAGMENTS:
        fragment = fragments[name][instance][offset:offset + width]
        if len(fragment) != width:
            raise ValueError(f"SM3 constructor fragment changed: {name}")
        library.append(fragment)
    compiler = forth_compiler(bytes(20), version)
    for name in ("sm2-double-point", "sm2-add-points"):
        library.append(compiler.emit(name, b""))
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


def encode_suffix(raw, references, library):
    """Serialize one compression plan and count its selected fragments."""
    cat = asm("OP_CAT")
    options = [entry.copy() for entry in references]
    cached = {}
    for index, fragment in enumerate(library):
        depth = len(library) - index
        copy = asm("OP_OVER") if depth == 1 else number(depth) + asm("OP_PICK")
        code = copy + cat
        cached[code] = fragment
        position = raw.find(fragment)
        while position != -1:
            keep_shorter(options[position], len(fragment), code)
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
    uses = Counter()
    copy_savings = Counter()
    cursor = 0
    while cursor < len(raw):
        start = cursor
        while cursor < len(raw) and choices[cursor] is None:
            cursor += 1
        if cursor != start:
            program.extend(push(raw[start:cursor]) + cat)
        if cursor < len(raw):
            width, code = choices[cursor]
            if code in cached:
                uses[cached[code]] += 1
            elif len(code) > 3 and width <= 256:
                # At a shallow depth a cached fragment needs a three-byte
                # PICK-and-append sequence. Measure savings on selected copies.
                copy_savings[raw[cursor:cursor + width]] += len(code) - 3
            program.extend(code)
            cursor += width
    program.extend(asm("OP_TOALTSTACK") + asm("OP_2DROP") * (len(library) // 2))
    program.extend(asm("OP_DROP") * (len(library) % 2) + asm("OP_FROMALTSTACK"))
    return bytes(program), uses, copy_savings


def compile_suffix(raw, library, *, optimize_library=False):
    """Encode literal runs, cached fragments and copies of earlier bytes."""
    references = [{} for _ in raw]
    earlier_spans(raw, references)
    baseline, uses, _ = encode_suffix(raw, references, library)
    if not optimize_library:
        return baseline

    reused = [fragment for fragment in library if uses[fragment] > 1]
    reduced, _, savings = encode_suffix(raw, references, reused)
    gains = {fragment: saving - len(push(fragment)) for fragment, saving in savings.items()
             if fragment not in reused and saving > len(push(fragment))}
    expanded = reused + sorted(gains, key=gains.get, reverse=True)
    augmented, uses, _ = encode_suffix(raw, references, expanded)
    # Place frequently used entries nearest the top, where picking is cheaper.
    ordered = sorted(expanded, key=uses.__getitem__)
    reordered, _, _ = encode_suffix(raw, references, ordered)
    return min((baseline, reduced, augmented, reordered), key=len)


def generate(version=TEMPLATE_VERSION):
    lock, offset = _canonical(version)
    prefix, suffix = lock[:offset], lock[offset + 20:]
    program = push(prefix) + compile_suffix(
        suffix, function_library(version), optimize_library=version != TEMPLATE_VERSION,
    )
    if evaluate(program) != ([prefix, suffix], []):
        raise ValueError("OTDA constructor does not reproduce the canonical SM2 template")
    return program


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination for the hexadecimal constructor")
    parser.add_argument("--version", type=int, choices=TEMPLATE_VERSIONS, default=TEMPLATE_VERSION)
    args = parser.parse_args()
    args.output.write_text(generate(args.version).hex() + "\n", encoding="ascii")

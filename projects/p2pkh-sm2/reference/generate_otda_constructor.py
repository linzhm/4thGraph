"""Rebuild the frozen OTDA constructors for canonical P2PKH-SM2 locks."""
import argparse
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from functools import cache, partial
from hashlib import sha256
import json
from pathlib import Path

from assemble import TEMPLATE_VERSION, TEMPLATE_VERSIONS, forth_compiler, sm3_blocks
from assemble import AFFINE_GENERATOR_TEMPLATE_VERSION, CARRIED_FIELD_TEMPLATE_VERSION, SPLIT_ROTATION_TEMPLATE_VERSION
from p2pkh_sm2 import MIXED_OTDA_VERSIONS, _canonical
from sm3_script import SPLIT_ROTATION_WRAP
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.compiler.script_builder import ScriptBuilder

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
CACHE_COMPILER = ScriptBuilder("REQUIRE stdlib/script-fragments.fth")


def function_library(version=TEMPLATE_VERSION):
    library = []
    # The split-rotation profile discovers reusable SM3 spans from its bytes.
    # Keep the original seed offsets for the historical constructors.
    if version < SPLIT_ROTATION_TEMPLATE_VERSION:
        fragments = {}
        sm3_blocks(version=version, fragments=fragments)
        for name, instance, offset, width in SM3_FRAGMENTS:
            fragment = fragments[name][instance][offset:offset + width]
            if len(fragment) != width:
                raise ValueError(f"SM3 constructor fragment changed: {name}")
            library.append(fragment)
    compiler = forth_compiler(bytes(20), version)
    for name in ("sm2-double-point", "sm2-add-points"):
        library.append(compiler.emit(name, b""))
    if version >= AFFINE_GENERATOR_TEMPLATE_VERSION:
        library.append(SPLIT_ROTATION_WRAP)
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


def trim_span(offset, width, source_size):
    program = b""
    if offset:
        program += number(offset) + asm("OP_SPLIT OP_NIP")
    if offset + width < source_size:
        program += number(width) + asm("OP_SPLIT OP_DROP")
    return program


def copy_span(offset, width, accumulator_size):
    return asm("OP_DUP") + trim_span(offset, width, accumulator_size)


@cache
def cache_pick(depth):
    return CACHE_COMPILER.emit("script-pick-depth", b"", depth)


def initialize_shared_cache(library):
    """Build each entry from literals or a matching span in an earlier entry."""
    cat = asm("OP_CAT")
    program = bytearray()
    for index, target in enumerate(library):
        shortest = push(target)
        for source_index, source in enumerate(library[:index]):
            common = SequenceMatcher(None, target, source, autojunk=False).get_matching_blocks()
            for start, offset, width in common:
                if not width:
                    continue
                prefix, suffix = target[:start], target[start+width:]
                depth = index - source_index - 1 + bool(prefix)
                copy = cache_pick(depth) + trim_span(offset, width, len(source))
                candidate = push(prefix) + copy + cat if prefix else copy
                if suffix:
                    candidate += push(suffix) + cat
                if len(candidate) < len(shortest):
                    shortest = candidate
        program.extend(shortest)
    return bytes(program)


def keep_shorter(options, length, program):
    prior = options.get(length)
    if prior is None or len(program) < len(prior):
        options[length] = program


def packed_repeat(width, copies, limit):
    """Repeat the top item exactly, with a bounded doubling-and-trim candidate."""
    bits = bin(copies)[3:]
    double = asm("OP_DUP OP_CAT")
    append = asm("OP_OVER OP_CAT")
    code = asm("OP_DUP") + b"".join(double + (append if bit == "1" else b"") for bit in bits) + asm("OP_NIP")
    doublings = (copies - 1).bit_length()
    if width * (1 << doublings) <= limit:
        sliced = double * doublings + number(width * copies) + asm("OP_SPLIT OP_DROP")
        return min(sliced, code, key=len)
    return code


def earlier_spans(raw, options, *, pack_runs=False):
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
            if pack_runs and count > 2 and count & (count - 1):
                keep_shorter(options[cursor], count * gap, source + packed_repeat(gap, count, len(raw)) + cat)
        matches.append(cursor)


def encode_suffix(raw, references, library, *, literal_runs=None, shared_cache=False):
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

    initializer = initialize_shared_cache(library) if shared_cache else b"".join(map(push, library))
    program = bytearray(initializer + asm("OP_0"))
    uses = Counter()
    copy_savings = Counter()
    cursor = 0
    while cursor < len(raw):
        start = cursor
        while cursor < len(raw) and choices[cursor] is None:
            cursor += 1
        if cursor != start:
            literal = raw[start:cursor]
            if literal_runs is not None:
                literal_runs.append(literal)
            program.extend(push(literal) + cat)
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


def literal_fragments(literal_runs, library):
    """Suggest four cache entries from bytes the first parse still pushes literally."""
    counts = Counter(literal[offset:offset+width] for literal in literal_runs for width in range(4, 32)
                     for offset in range(len(literal)-width+1))
    gains = {fragment: (len(fragment)-3)*uses-len(push(fragment)) for fragment, uses in counts.items()
             if uses > 1 and fragment not in library}
    return sorted((fragment for fragment, gain in gains.items() if gain > 0),
                  key=gains.__getitem__, reverse=True)[:4]


def follow_up_cache(encode, library):
    """Try one bounded batch of substitutions from the selected encoding."""
    literals = []
    baseline, _, savings = encode(library, literal_runs=literals)
    trials = [baseline]
    for index in range(len(library)):
        code, _, _ = encode(library[:index] + library[index+1:])
        trials.append(code)
    from_literals = literal_fragments(literals, library)
    from_copies = sorted((fragment for fragment, saving in savings.items()
                          if fragment not in library and saving > len(push(fragment))),
                         key=lambda fragment: savings[fragment] - len(push(fragment)), reverse=True)[:4]
    proposals = [[fragment] for fragment in from_literals[:2] + from_copies[:3]]
    for additions in (*proposals, from_literals, from_copies):
        if not additions:
            continue
        expanded = [*library, *additions]
        _, uses, _ = encode(expanded)
        retained = sorted((fragment for fragment in expanded if uses[fragment] > 1), key=uses.__getitem__)
        code, _, _ = encode(retained)
        trials.append(code)
    return min(trials, key=len)


def evaluate_cache_plans(encode, library, *, optimize_library, refine_library, follow_up=False):
    baseline, uses, _ = encode(library)
    if not optimize_library:
        return baseline, baseline

    reused = [fragment for fragment in library if uses[fragment] > 1]
    reduced, _, savings = encode(reused)
    gains = {fragment: saving - len(push(fragment)) for fragment, saving in savings.items()
             if fragment not in reused and saving > len(push(fragment))}
    expanded = reused + sorted(gains, key=gains.get, reverse=True)
    augmented, uses, _ = encode(expanded)
    # Place frequently used entries nearest the top, where picking is cheaper.
    ordered = sorted(expanded, key=uses.__getitem__)
    literal_runs = [] if refine_library else None
    reordered, _, _ = encode(ordered, literal_runs=literal_runs)
    _, starting_cache = min(zip((baseline, reduced, augmented, reordered), (library, reused, expanded, ordered)),
                            key=lambda pair: len(pair[0]))
    candidates = [baseline, reduced, augmented, reordered]
    if literal_runs:
        proposed = ordered + literal_fragments(literal_runs, ordered)
        _, uses, _ = encode(proposed)
        retained = sorted((fragment for fragment in proposed if uses[fragment] > 1), key=uses.__getitem__)
        rescored, _, _ = encode(retained)
        candidates.append(rescored)
        # Removing even a reused entry can lower copy costs for the other entries.
        for index in range(len(retained)):
            pruned, _, _ = encode(retained[:index] + retained[index+1:])
            candidates.append(pruned)
    best = min(candidates, key=len)
    return best, min(best, follow_up_cache(encode, starting_cache), key=len) if follow_up else best


def suffix_plans(raw, library, *, optimize_library=False, refine_library=False, share_cache=False):
    references = [{} for _ in raw]
    earlier_spans(raw, references, pack_runs=share_cache)
    encode = partial(encode_suffix, raw, references)
    literal, _ = evaluate_cache_plans(encode, library, optimize_library=optimize_library, refine_library=refine_library)
    plans = {"literal-cache": literal}
    if share_cache:
        shared, tuned = evaluate_cache_plans(partial(encode, shared_cache=True), library,
                                            optimize_library=True, refine_library=True, follow_up=True)
        plans.update({"shared-cache": shared, "shared-cache-follow-up": tuned})
    return plans


def compile_suffix(raw, library, *, optimize_library=False, refine_library=False):
    return suffix_plans(raw, library, optimize_library=optimize_library,
                        refine_library=refine_library)["literal-cache"]


def generate(version=TEMPLATE_VERSION, *, report=None):
    lock, offset = _canonical(version)
    prefix, suffix = lock[:offset], lock[offset + 20:]
    plans = suffix_plans(
        suffix, function_library(version), optimize_library=version != TEMPLATE_VERSION,
        refine_library=version >= CARRIED_FIELD_TEMPLATE_VERSION,
        share_cache=version >= CARRIED_FIELD_TEMPLATE_VERSION,
    )
    constructors = {name: push(prefix) + program for name, program in plans.items()}
    for name, program in constructors.items():
        if evaluate(program) != ([prefix, suffix], []):
            raise ValueError(f"OTDA constructor {name} does not reproduce the canonical SM2 template")
    selected = min(constructors, key=lambda name: len(constructors[name]))
    if report is not None:
        report.update(template_version=version, lock_sha256=sha256(lock).hexdigest(), selected=selected,
                      candidates={name: {"bytes": len(program), "sha256": sha256(program).hexdigest()}
                                  for name, program in constructors.items()})
    return constructors[selected]


def generate_mixed():
    fixed_parts = []
    for version in MIXED_OTDA_VERSIONS:
        lock, offset = _canonical(version)
        fixed_parts.extend((lock[:offset], lock[offset + 20:]))
    prefix_a, suffix_a, prefix_b, suffix_b = fixed_parts
    prefixes = push(prefix_a) + (asm("OP_DUP") if prefix_a == prefix_b else push(prefix_b))
    suffixes = compile_suffix(suffix_a + suffix_b, function_library(MIXED_OTDA_VERSIONS[-1]),
                              optimize_library=True)
    # Leave each prefix next to its suffix, in canonical template order.
    program = prefixes + suffixes + number(len(suffix_a)) + asm("OP_SPLIT OP_ROT OP_SWAP")
    if evaluate(program) != (fixed_parts, []):
        raise ValueError("mixed OTDA constructor does not reproduce both SM2 templates")
    return {
        "templates": list(MIXED_OTDA_VERSIONS),
        "bytes": len(program),
        "sha256": sha256(program).hexdigest(),
        "program_hex": program.hex(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination for the constructor")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--version", type=int, choices=TEMPLATE_VERSIONS, default=TEMPLATE_VERSION)
    group.add_argument("--mixed", action="store_true", help="generate the combined template 6 and 7 JSON")
    parser.add_argument("--report", type=Path, help="write the comparison of single-template constructor plans")
    args = parser.parse_args()
    if args.mixed and args.report:
        parser.error("--report requires a single-template constructor")
    report = {} if args.report else None
    encoded = json.dumps(generate_mixed(), indent=2) if args.mixed else generate(args.version, report=report).hex()
    args.output.write_text(encoded + "\n", encoding="ascii")
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

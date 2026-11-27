"""Choose the Script encoding of a complete, already authorized preimage."""
from dataclasses import dataclass, replace
from functools import lru_cache
from hashlib import sha256
from os.path import commonprefix

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.otda_reconstruction import push_repeated_bytes, reconstruct_mixed
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.bsv.transaction import CHRONICLE, SIGHASH_ALL, SIGHASH_SINGLE, compact


@dataclass(frozen=True)
class PreimagePlan:
    selected: str
    program: bytes
    candidates: tuple[dict, ...]


def _copy_span(depth, start, width, total):
    code = (asm("OP_DUP") if depth == 0 else asm("OP_OVER") if depth == 1 else
            number(depth) + asm("OP_PICK"))
    if start:
        code += number(start) + asm("OP_SPLIT OP_NIP")
    if start + width < total:
        code += number(width) + asm("OP_SPLIT OP_DROP")
    return code


@lru_cache(maxsize=32)
def _shared_templates(patterns):
    """Reuse exact prefixes and suffixes from earlier dictionary entries."""
    parts = tuple(part for pattern in patterns for part in pattern.fixed_parts)
    code = bytearray()
    for i, part in enumerate(parts):
        best = push_repeated_bytes(part)
        for j, previous in enumerate(parts[:i]):
            depth = i - j - 1
            if part == previous:
                best = min(best, _copy_span(depth, 0, len(part), len(part)), key=len)
                continue
            prefix = len(commonprefix((part, previous)))
            suffix = len(commonprefix((part[::-1], previous[::-1])))
            if prefix:
                copied = _copy_span(depth, 0, prefix, len(previous))
                proposal = (copied + push_repeated_bytes(part[prefix:]) + asm("OP_CAT")
                            if prefix < len(part) else copied)
                best = min(best, proposal, key=len)
            if suffix:
                copied = _copy_span(depth + int(suffix < len(part)), len(previous) - suffix, suffix, len(previous))
                proposal = (push_repeated_bytes(part[:-suffix]) + copied + asm("OP_CAT")
                            if suffix < len(part) else copied)
                best = min(best, proposal, key=len)
        code.extend(best)
    return bytes(code)


def _encodings(tx, index, auth, patterns, chronicle_active, mode):
    yield "literal", push(auth.preimage), None
    if mode == "literal":
        return
    base = auth.requested_type & 31
    if (tx.version != 2 or chronicle_active is not True or auth.companion
            or not auth.requested_type & CHRONICLE or base not in (SIGHASH_ALL, SIGHASH_SINGLE)):
        yield "reconstruct", None, "requires active version-2 OTDA ALL or paired SINGLE"
        return
    if base == SIGHASH_SINGLE and index >= len(tx.outputs):
        yield "reconstruct", None, "requires an output at the signing input index"
        return

    outputs = tx.outputs if base == SIGHASH_ALL else (tx.outputs[index],)
    yield "repeat-preimage", push_repeated_bytes(auth.preimage), None
    matched = False
    for rendering in ("literal", "repeated"):
        rendered = (patterns if rendering == "repeated" else
                    tuple(replace(p, program=b"".join(map(push, p.fixed_parts))) for p in patterns))
        for position, pattern in enumerate(rendered):
            if (program := pattern.build(auth.preimage, outputs)) is not None:
                matched = True
                yield f"template-{position}/{rendering}", program, None
        if len(rendered) > 1:
            if (program := reconstruct_mixed(auth.preimage, outputs, rendered)) is not None:
                yield f"mixed/{rendering}", program, None
    if len(patterns) > 1:
        program = reconstruct_mixed(auth.preimage, outputs, patterns, combine_programs=_shared_templates)
        if program is not None:
            yield "mixed/shared", program, None
    if not matched:
        yield "templates", None, "no approved template matches a committed output"


def compile_preimage(tx, index, auth, patterns=(), *, chronicle_active, mode="auto",
                     witness_tail_bytes=0, max_payload_bytes=None):
    """Validate and rank encodings by their complete serialized input Script field."""
    if mode not in ("auto", "literal"):
        raise ValueError("preimage constructor mode must be auto or literal")
    if not 0 <= index < len(tx.inputs):
        raise ValueError("preimage constructor input index is out of range")
    if type(witness_tail_bytes) is not int or witness_tail_bytes < 0:
        raise ValueError("witness_tail_bytes must be nonnegative")
    if max_payload_bytes is not None and (type(max_payload_bytes) is not int or max_payload_bytes < 0):
        raise ValueError("max_payload_bytes must be nonnegative")

    entries = []
    selected = None
    for name, code, reason in _encodings(tx, index, auth, tuple(patterns), chronicle_active, mode):
        entry = {"name": name, "eligible": False}
        entries.append(entry)
        if code is None:
            entry["reason"] = reason
            continue
        peak = 0

        def observe(main, alt):
            nonlocal peak
            peak = max(peak, sum(map(len, main)) + sum(map(len, alt)))

        try:
            result = evaluate(code, observe_stack=observe)
        except ScriptError:
            result = None
        length = len(code) + witness_tail_bytes
        cost = len(compact(length)) + length
        entry.update(script_bytes=len(code), input_field_bytes=cost,
                     peak_constructor_payload_bytes=peak, sha256=sha256(code).hexdigest())
        if result != ([auth.preimage], []):
            entry["reason"] = "constructor does not reproduce the complete preimage"
        elif max_payload_bytes is not None and peak > max_payload_bytes:
            entry["reason"] = "constructor exceeds the payload limit"
        else:
            entry["eligible"] = True
            if selected is None or cost < selected[0]:
                selected = cost, name, code
    if selected is None:
        raise ValueError("no preimage encoding satisfies the constructor requirements")
    return PreimagePlan(selected[1], selected[2], tuple(entries))

"""Construct exact verifier funding bytes in a Chronicle version-2 unlock."""

from collections import Counter, defaultdict, deque

from shared.script import asm, number, push


_COPY_HEAD = asm("OP_DUP")
_COPY_FROM = asm("OP_SPLIT OP_NIP")
_COPY_SIZE = asm("OP_SPLIT OP_DROP")
_APPEND = asm("OP_CAT")


def _copy_previous(start: int, size: int, written: int) -> bytes:
    """Append a substring of the already reconstructed bytes."""
    code = _COPY_HEAD
    if start:
        code += number(start) + _COPY_FROM
    if start + size != written:
        code += number(size) + _COPY_SIZE
    return code + _APPEND


def _matching_size(raw: bytes, start: int, cursor: int, seed: int) -> int:
    """Find the longest non-overlapping match with C-backed byte comparisons."""
    limit = min(cursor - start, len(raw) - cursor)
    low = seed
    high = min(seed * 2, limit)
    while high > low and raw[start:start + high] == raw[cursor:cursor + high]:
        low = high
        high = min(high * 2, limit)
    while low + 1 < high:
        probe = (low + high) // 2
        if raw[start:start + probe] == raw[cursor:cursor + probe]:
            low = probe
        else:
            high = probe
    return low


def _fragments(raw):
    """Plan literal spans and copies from the reconstructed prefix."""
    seed = 12
    recent = defaultdict(lambda: deque(maxlen=8))
    pending = cursor = indexed = 0
    while cursor + seed <= len(raw):
        while indexed + seed <= cursor:
            recent[raw[indexed:indexed + seed]].append(indexed)
            indexed += 1
        best_start = best_size = 0
        for start in recent.get(raw[cursor:cursor + seed], ()):
            size = _matching_size(raw, start, cursor, seed)
            if size > best_size:
                best_start, best_size = start, size
        if not best_size:
            cursor += 1
            continue
        step = _copy_previous(best_start, best_size, cursor)
        if best_size <= len(step) + 2:
            cursor += 1
            continue
        if cursor > pending:
            literal = raw[pending:cursor]
            yield literal, push(literal) + _APPEND
        yield raw[cursor:cursor + best_size], step
        cursor += best_size
        pending = cursor
    if pending < len(raw):
        literal = raw[pending:]
        yield literal, push(literal) + _APPEND


def reconstruction_script(raw: bytes, *, share_fragments: bool = False) -> bytes:
    """Leave the exact serialized bytes on stack, using at most 16 shared fragments."""
    if type(raw) is not bytes or not raw:
        raise ValueError("expected nonempty serialized funding transaction bytes")
    fragments = tuple(_fragments(raw))
    original = push(b"") + b"".join(step for _, step in fragments)
    if not share_fragments:
        return original

    # All lookups are at most three bytes (1..16 OP_PICK OP_CAT).
    # Each dictionary entry costs its push and an OP_NIP at the end.
    savings = Counter()
    for fragment, step in fragments:
        savings[fragment] += max(0, len(step) - 3)
    candidates = ((value, gain - len(push(value)) - 1) for value, gain in savings.items())
    ranked = sorted(candidates, key=lambda item: -item[1])
    dictionary = tuple(value for value, gain in ranked[:16] if gain > 0)
    if not dictionary:
        return original
    lookup = {value: number(depth) + asm("OP_PICK OP_CAT") for depth, value in enumerate(dictionary, 1)}
    lookup[dictionary[0]] = asm("OP_OVER OP_CAT")
    reconstructed = (
        b"".join(push(value) for value in reversed(dictionary)) + push(b"")
        + b"".join(min(step, lookup.get(fragment, step), key=len) for fragment, step in fragments)
        + asm("OP_NIP") * len(dictionary)
    )
    return min(original, reconstructed, key=len)

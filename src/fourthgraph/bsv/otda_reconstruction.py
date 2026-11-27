"""Reconstruct the trailing outputs of an OTDA preimage from fixed templates."""
from dataclasses import dataclass

from fourthgraph.bsv.script import asm, number, push


def _repeated_run(data):
    """Find a run of at least eight identical blocks in a fixed byte string."""
    marker_width = 12
    previous = {}
    for second in range(len(data) - marker_width + 1):
        marker = data[second:second + marker_width]
        start = previous.get(marker)
        previous[marker] = second
        if start is None:
            continue
        width = second - start
        if width < marker_width or start + 8 * width > len(data):
            continue
        block = data[start:second]
        if not data.startswith(block * 7, second):
            continue
        end = start + 8 * width
        while data.startswith(block, end):
            end += width
        return start, block, end
    return None


def push_repeated_bytes(data):
    """Emit a Script that leaves exactly one fixed byte string on the stack."""
    parts = []
    while (run := _repeated_run(data)) is not None:
        start, block, end = run
        if start:
            parts.append(push(data[:start]))
        size = end - start
        copies = size // len(block)
        doublings = (copies - 1).bit_length()
        expanded = push(block) + asm("OP_DUP OP_CAT") * doublings
        if copies != 1 << doublings:
            expanded += number(size) + asm("OP_SPLIT OP_DROP")
        literal = push(data[start:end])
        parts.append(min(literal, expanded, key=len))
        data = data[end:]
    if not parts:
        return push(data)
    if data:
        parts.append(push(data))
    return parts[0] + b"".join(part + asm("OP_CAT") for part in parts[1:])


@dataclass(frozen=True)
class Reconstruction:
    program: bytes
    fixed_parts: tuple[bytes, ...]
    field_sizes: tuple[int, ...]

    def match(self, script):
        """Return the variable fields only when every fixed byte matches."""
        position = 0
        fields = []
        for fixed, width in zip(self.fixed_parts[:-1], self.field_sizes, strict=True):
            if not script.startswith(fixed, position):
                return None
            position += len(fixed)
            fields.append(script[position:position + width])
            position += width
        return tuple(fields) if script[position:] == self.fixed_parts[-1] and position <= len(script) else None

    def build(self, preimage, outputs, *, encode_prefix=push):
        """Replace a contiguous suffix of real outputs; preserve all preceding bytes."""
        slots = [(output, self.match(output.script), 0) for output in outputs]
        if not any(fields is not None for _, fields, _ in slots):
            return None
        return _build(preimage, slots, (self,), encode_prefix=encode_prefix)


def reconstruct_mixed(preimage, outputs, patterns, *, combine_programs=None):
    """Serialize outputs in signed order with the dictionaries actually used.

    A combined program must leave the same dictionary parts, in the same
    order, as running each selected constructor. Return None to use those
    constructors individually.
    """
    slots = []
    used = set()
    for output in outputs:
        for index, pattern in enumerate(patterns):
            fields = pattern.match(output.script)
            if fields is not None:
                used.add(index)
                slots.append((output, fields, index))
                break
        else:
            slots.append((output, None, None))
    if len(used) < 2:
        return None
    order = sorted(used)
    remap = {index: position for position, index in enumerate(order)}
    selected = tuple(patterns[index] for index in order)
    return _build(
        preimage,
        [(output, fields, remap.get(index)) for output, fields, index in slots],
        selected,
        constructor=combine_programs(selected) if combine_programs is not None else None,
    )


def shorter_reconstruction(preimage, outputs, patterns):
    """Select a fixed-output constructor only when it beats a literal push."""
    if not patterns:
        return None
    programs = [pattern.build(preimage, outputs) for pattern in patterns]
    if len(patterns) > 1:
        programs.append(reconstruct_mixed(preimage, outputs, patterns))
    literal_size = len(push(preimage))
    return min((code for code in programs if code is not None and len(code) < literal_size), key=len, default=None)


def _build(preimage, slots, patterns, *, constructor=None, encode_prefix=push):
    encoded = b"".join(output.serialize() for output, _, _ in slots)
    if not preimage.endswith(encoded, 0, len(preimage) - 8):
        raise ValueError("OTDA outputs differ from the signing preimage")

    cat = asm("OP_CAT")
    count = sum(len(pattern.fixed_parts) for pattern in patterns)
    base_depth = []
    next_depth = count
    for pattern in patterns:
        base_depth.append(next_depth)
        next_depth -= len(pattern.fixed_parts)

    program = bytearray(
        b"".join(pattern.program for pattern in patterns) if constructor is None else constructor
    )
    program.extend(encode_prefix(preimage[:-len(encoded) - 8]))
    for output, fields, index in slots:
        raw = output.serialize()
        if fields is None:
            program.extend(push(raw) + cat)
            continue
        program.extend(push(raw[:-len(output.script)]) + cat)
        depth = base_depth[index]
        for value in fields:
            program.extend(number(depth) + asm("OP_PICK OP_CAT") + push(value) + cat)
            depth -= 1
        program.extend(asm("OP_OVER OP_CAT") if depth == 1 else number(depth) + asm("OP_PICK OP_CAT"))
    program.extend(push(preimage[-8:]) + cat)
    if count == 2:
        # Keep the original R1 single-dictionary wire encoding.
        program.extend(asm("OP_ROT OP_DROP OP_SWAP OP_DROP"))
    else:
        program.extend(asm("OP_TOALTSTACK") + asm("OP_2DROP") * (count // 2)
                       + asm("OP_DROP") * (count % 2) + asm("OP_FROMALTSTACK"))
    return bytes(program)

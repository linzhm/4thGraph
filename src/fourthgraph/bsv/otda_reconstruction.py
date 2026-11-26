"""Reconstruct the trailing outputs of an OTDA preimage from fixed templates."""
from dataclasses import dataclass

from fourthgraph.bsv.script import asm, number, push


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

    def build(self, preimage, outputs):
        """Replace a contiguous suffix of real outputs; preserve all preceding bytes."""
        slots = [(output, self.match(output.script), 0) for output in outputs]
        if not any(fields is not None for _, fields, _ in slots):
            return None
        return _build(preimage, slots, (self,))


def reconstruct_mixed(preimage, outputs, patterns):
    """Emit each used dictionary once and serialize all outputs in signed order."""
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
    return _build(
        preimage,
        [(output, fields, remap.get(index)) for output, fields, index in slots],
        tuple(patterns[index] for index in order),
    )


def _build(preimage, slots, patterns):
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

    program = bytearray()
    for pattern in patterns:
        program.extend(pattern.program)
    program.extend(push(preimage[:-len(encoded) - 8]))
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

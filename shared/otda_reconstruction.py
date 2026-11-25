"""Reconstruct the trailing outputs of an OTDA preimage from fixed templates."""
from dataclasses import dataclass

from .script import asm, number, push


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
        slots = [(output, self.match(output.script)) for output in outputs]
        if not any(fields is not None for _, fields in slots):
            return None
        encoded = b"".join(output.serialize() for output, _ in slots)
        if not preimage.endswith(encoded, 0, len(preimage) - 8):
            raise ValueError("OTDA outputs differ from the signing preimage")

        cat = asm("OP_CAT")
        count = len(self.fixed_parts)
        program = bytearray(self.program + push(preimage[:-len(encoded) - 8]))
        for output, fields in slots:
            raw = output.serialize()
            if fields is None:
                program.extend(push(raw) + cat)
                continue
            program.extend(push(raw[:-len(output.script)]) + cat)
            for depth, value in zip(range(count, 1, -1), fields, strict=True):
                program.extend(number(depth) + asm("OP_PICK OP_CAT") + push(value) + cat)
            program.extend(asm("OP_OVER OP_CAT"))
        program.extend(push(preimage[-8:]) + cat)
        if count == 2:
            # Keep the original R1 wire encoding.
            program.extend(asm("OP_ROT OP_DROP OP_SWAP OP_DROP"))
        else:
            program.extend(asm("OP_TOALTSTACK") + asm("OP_2DROP") * (count // 2)
                           + asm("OP_DROP") * (count % 2) + asm("OP_FROMALTSTACK"))
        return bytes(program)

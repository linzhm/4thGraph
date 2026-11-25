"""Plain BLS12-381 R1CS tapes and witness evaluation for the Python prover."""

import mmap
import sys
from struct import Struct, pack

from field import R


HEADER = Struct("<8s6Q")
SECTION = Struct("<IQ")
WORD = Struct("<I")
FIELD_BYTES = 32
HINT_FLAG = 1 << 31
CONSTANT_WIRE = (1 << 32) - 1


class UnsatisfiedConstraint(ValueError):
    """A well-formed proving request violates the R1CS."""


class R1CS:
    def __init__(self, path):
        if sys.byteorder != "little":
            raise RuntimeError("the R1CS tape reader requires a little-endian host")
        with path.open("rb") as source:
            self.file = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            magic, self.rows, self.wires, self.n_public, self.n_secret, count, words = HEADER.unpack_from(self.file)
            start = HEADER.size
            end = start + FIELD_BYTES * count
            if (magic != b"R1CSPY01" or len(self.file) != end + words * 4
                    or not 0 < self.n_public + self.n_secret <= self.wires or not self.rows):
                raise ValueError("invalid BLS12-381 R1CS tape")
            self.coefficients = tuple(int.from_bytes(self.file[i:i + FIELD_BYTES], "big")
                                      for i in range(start, end, FIELD_BYTES))
            if self.coefficients[:5] != (0, 1, 2, R - 1, R - 2) or any(c >= R for c in self.coefficients):
                raise ValueError("noncanonical R1CS coefficients")
            self.words = memoryview(self.file)[end:].cast("I")
        except BaseException:
            self.file.close()
            raise

    def close(self):
        self.words.release()
        self.file.close()

    def export(self, path):
        """Export the same constraints and wire order as a standard Circom R1CS."""
        public_inputs = self.n_public - 1
        header = pack("<I32sIIIIQI", FIELD_BYTES, R.to_bytes(FIELD_BYTES, "little"),
                      self.wires, 0, public_inputs, self.n_secret, self.wires, self.rows)
        columns = tuple(value.to_bytes(FIELD_BYTES, "little") for value in self.coefficients)
        tape = self.words
        position = rows = 0
        with path.open("xb", buffering=4 << 20) as output:
            output.write(pack("<4sII", b"r1cs", 1, 3))
            output.write(SECTION.pack(1, len(header)))
            output.write(header)
            section = output.tell()
            output.write(SECTION.pack(2, 0))
            size = 0
            while position < len(tape):
                tag = tape[position]
                end = position + (tag & (HINT_FLAG - 1))
                if end <= position or end > len(tape):
                    raise ValueError("truncated R1CS tape instruction")
                if not tag & HINT_FLAG:
                    cursor = position + 4
                    record = bytearray()
                    for count in tape[position + 1:cursor]:
                        terms = {}
                        for _ in range(count):
                            coef, wire = tape[cursor], tape[cursor + 1]
                            cursor += 2
                            if coef:
                                wire = 0 if wire == CONSTANT_WIRE else wire
                                if wire in terms:
                                    raise ValueError("repeated wire in exported R1CS expression")
                                terms[wire] = columns[coef]
                        record += WORD.pack(len(terms))
                        for wire, value in terms.items():
                            record += WORD.pack(wire)
                            record += value
                    if cursor != end:
                        raise ValueError("unexpected R1CS row structure")
                    output.write(record)
                    size += len(record)
                    rows += 1
                position = end
            if rows != self.rows:
                raise ValueError("unexpected number of R1CS rows")
            output.seek(section)
            output.write(SECTION.pack(2, size))
            output.seek(0, 2)
            output.write(SECTION.pack(3, self.wires * 8))
            for start in range(0, self.wires, 1 << 16):
                output.write(b"".join(pack("<Q", wire) for wire in range(start, min(start + (1 << 16), self.wires))))

    def _hint(self, tape, ptr, end, wires):
        opname, inputs = tape[ptr:ptr + 2]
        ptr += 2
        args = []
        for _ in range(inputs):
            count = tape[ptr]
            ptr += 1
            value = 0
            for _ in range(count):
                coef, wire = tape[ptr], tape[ptr + 1]
                ptr += 2
                value += self.coefficients[coef] * (1 if wire == CONSTANT_WIRE else wires[wire])
            args.append(value % R)
        if ptr + 2 != end:
            raise ValueError("invalid R1CS hint instruction")
        start, stop = tape[ptr:ptr + 2]
        if not 0 < start < stop <= len(wires):
            raise ValueError("R1CS hint output outside witness")
        if opname == 1 and len(args) == 1:
            values = [(args[0] >> bit) & 1 for bit in range(stop - start)]
        elif opname == 2 and len(args) == 1 and stop == start + 1:
            values = [pow(args[0], -1, R) if args[0] else 0]
        else:
            raise ValueError("unsupported plain R1CS hint")
        if any(wires[index] is not None for index in range(start, stop)):
            raise ValueError("R1CS hint overwrites an assigned wire")
        wires[start:stop] = values

    def solve(self, public, private):
        """Return the full checked witness in standard wire order."""
        if len(public) + 1 != self.n_public or len(private) != self.n_secret:
            raise ValueError("public or private circuit input count differs from R1CS")
        if any(not 0 <= value < R for value in (*public, *private)):
            raise ValueError("noncanonical circuit input")
        wires = [1, *public, *private] + [None] * (self.wires - self.n_public - self.n_secret)
        tape, coefficients = self.words, self.coefficients
        position = row = 0
        while position < len(tape):
            tag = tape[position]
            end = position + (tag & (HINT_FLAG - 1))
            if end <= position or end > len(tape):
                raise ValueError("truncated R1CS tape instruction")
            if tag & HINT_FLAG:
                self._hint(tape, position + 1, end, wires)
                position = end
                continue

            lengths = tape[position + 1:position + 4]
            cursor = position + 4
            sums = [0, 0, 0]
            unknown = None
            for column, count in enumerate(lengths):
                total = 0
                for _ in range(count):
                    coef, wire = tape[cursor], tape[cursor + 1]
                    cursor += 2
                    if not coef:
                        continue
                    value = 1 if wire == CONSTANT_WIRE else wires[wire]
                    if value is None:
                        if unknown is not None:
                            raise ValueError(f"multiple unassigned terms in R1CS row {row}")
                        unknown = column, wire, coef
                    elif coef == 1:
                        total += value
                    elif coef == 3:
                        total -= value
                    else:
                        total += value * coefficients[coef]
                sums[column] = total if 0 <= total < R else total % R
            if cursor != end or row >= self.rows:
                raise ValueError("unexpected R1CS row structure")
            if unknown is not None:
                column, wire, coef = unknown
                a, b, c = sums
                if column == 2:
                    term = (a * b - c) % R
                else:
                    divisor = sums[1 - column]
                    term = (c * pow(divisor, -1, R) - sums[column]) % R if divisor else 0
                sums[column] = (sums[column] + term) % R
                if coef == 1:
                    wires[wire] = term
                elif coef == 3:
                    wires[wire] = (-term) % R
                else:
                    wires[wire] = term * pow(coefficients[coef], -1, R) % R
            if sums[0] * sums[1] % R != sums[2]:
                raise UnsatisfiedConstraint(f"R1CS row {row} is unsatisfied")
            position = end
            row += 1
        if row != self.rows or None in wires:
            raise ValueError("R1CS tape did not solve all rows and witnesses")
        return wires

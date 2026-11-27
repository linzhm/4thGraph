"""Generate an OTDA preimage reconstruction program with shared P-256 kernels."""
import re

from assemble import assemble
from fourthgraph.bsv.script import number, push


def shared_kernel_program(prefix, suffix, *, injected=None):
    def block(name):
        return assemble(bytes(20), compiled_curve=True, entry=name, injected=injected)

    kernels = (block("DOUBLE_POINT"), block("ADD_POINTS"))
    fragments = re.compile(b"|".join(re.escape(kernel) for kernel in reversed(kernels)))

    def append_fragment(raw, *, nested):
        # Stack: double add prefix suffix [block-accumulator].
        program = bytearray()
        start = 0
        for match in fragments.finditer(raw):
            if match.start() > start:
                program.extend(push(raw[start:match.start()]) + b"\x7e")
            depth = 3 + nested - kernels.index(match.group())
            program.extend(number(depth) + b"\x79\x7e")  # OP_PICK OP_CAT
            start = match.end()
        if start < len(raw):
            program.extend(push(raw[start:]) + b"\x7e")
        return min(push(raw) + b"\x7e", bytes(program), key=len)

    program = bytearray(push(kernels[0]) + push(kernels[1]) + push(prefix) + b"\x00")
    remaining = suffix
    for name in ("DIGITS_SPLIT4", "STEP_SPLIT4"):
        fragment = block(name)
        literal, remaining = remaining.split(fragment * 64)
        program.extend(append_fragment(literal, nested=False))
        encoded = min(push(fragment), b"\x00" + append_fragment(fragment, nested=True), key=len)
        program.extend(encoded + b"\x76\x7e" * 6 + b"\x7e")
    program.extend(append_fragment(remaining, nested=False))
    program.extend(b"\x72\x6d")  # OP_2SWAP OP_2DROP; leave prefix and suffix.
    return bytes(program)

"""Select fixed-width byte kernels and provably equivalent constant encodings."""

from hashlib import sha256

from fourthgraph.bsv.script import asm, number
from .call_sites import emit_bound_calls, emit_library_kernel
from .script_builder import ScriptBuilder, build_word


LIBRARY = "std/byte-layout"
SPLIT = "byte-reverse-fields-split"
PACKED = "byte-reverse-six-fields"
LITERAL = "byte-constant-literal"
REPEAT = "byte-constant-repeat"


def unbound(*_):
    raise ValueError("byte layout operations require a call-site plan")


REVERSE_FIELDS = build_word("script cell", "script", unbound)
BYTE_CONSTANT = build_word("script bytes", "script", unbound)


class ByteLayoutBuilder(ScriptBuilder):
    def __init__(self, source):
        super().__init__(source, vocabulary={"reverse-32-fields": REVERSE_FIELDS, "byte-constant": BYTE_CONSTANT})

    def emit_plan(self, entry, bindings):
        operations = ((REVERSE_FIELDS, self.lower_reverse), (BYTE_CONSTANT, self.lower_constant))
        return emit_bound_calls(self, entry, bindings, operations)

    def lower_reverse(self, token, site, name, count):
        if not 1 <= count <= 6:
            raise token.error("byte reversal requires one to six 32-byte fields")
        name = SPLIT if name is None else name
        if name not in (SPLIT, PACKED):
            raise token.error(f"kernel {name!r} has the wrong operation for call site {site}")
        choices = [{"kernel": SPLIT, "eligible": True}, {"kernel": PACKED, "eligible": count == 6}]
        if count != 6:
            choices[1]["reason"] = "packed reversal requires exactly six 32-byte fields"
            if name == PACKED:
                raise token.error(choices[1]["reason"])
        guard = asm("OP_SIZE") + number(32 * count) + asm("OP_NUMEQUALVERIFY")
        operands = (count,) if name == SPLIT else ()
        code, selected = emit_library_kernel(self, name, LIBRARY, token, site, *operands)
        return guard + code, {"operation": "reverse-32-fields", "candidates": choices,
                              "evidence": {"kind": "build-field-count", "count": count,
                                           "field_bytes": 32, "checked_input_bytes": 32 * count},
                              "guard_bytes": len(guard), "adapter_bytes": len(guard), **selected}

    def lower_constant(self, token, site, name, data):
        if len(data) > 4096:
            raise token.error("byte constants are limited to 4096 bytes in this target")
        name = LITERAL if name is None else name
        if name not in (LITERAL, REPEAT):
            raise token.error(f"kernel {name!r} has the wrong operation for call site {site}")
        seed, doubles = data, 0
        while seed and len(seed) % 2 == 0:
            half = len(seed) // 2
            if seed[:half] != seed[half:]:
                break
            seed = seed[:half]
            doubles += 1
        choices = [{"kernel": LITERAL, "eligible": True}, {"kernel": REPEAT, "eligible": doubles > 0}]
        if not doubles:
            choices[1]["reason"] = "constant has no adjacent identical halves"
            if name == REPEAT:
                raise token.error(choices[1]["reason"])
        operands = (seed, doubles) if name == REPEAT else (data,)
        code, selected = emit_library_kernel(self, name, LIBRARY, token, site, *operands)
        return code, {"operation": "byte-constant", "candidates": choices,
                      "evidence": {"kind": "build-bytes", "literal_bytes": len(data),
                                   "literal_sha256": sha256(data).hexdigest(),
                                   "seed_bytes": len(seed), "doublings": doubles},
                      "guard_bytes": 0, "adapter_bytes": 0, **selected}

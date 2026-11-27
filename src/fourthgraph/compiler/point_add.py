"""Bind the same point-add operation to a compatible standard-library kernel."""

from dataclasses import dataclass

from fourthgraph.bsv.script import SECP256K1_FIELD as FIELD, asm, number
from .call_sites import emit_bound_calls, emit_library_kernel
from .script_builder import ScriptBuilder, build_word


@dataclass(frozen=True)
class Kernel:
    curve: str
    library: str
    affine_rhs: bool = False


GENERAL = "secp256k1-add"
AFFINE = "secp256k1-add-affine"
GUARDED = "secp256k1-add-affine-guarded"
KERNELS = {
    GENERAL: Kernel("secp256k1", "std/secp256k1"),
    AFFINE: Kernel("secp256k1", "std/secp256k1", affine_rhs=True),
    "p256-add": Kernel("p256", "std/p256"),
}


def fixed_operand(encoded):
    if not encoded:
        return ()
    if len(encoded) != 64:
        raise ValueError("point-add needs two 32-byte affine coordinates or a runtime right operand")
    x, y = int.from_bytes(encoded[:32], "big"), int.from_bytes(encoded[32:], "big")
    if x >= FIELD or y >= FIELD or (y * y - x * x * x - 7) % FIELD:
        raise ValueError("constant right operand is outside the secp256k1 curve")
    return x, y


def unbound(*_):
    raise ValueError("secp256k1-point-add requires a call-site plan")


POINT_ADD = build_word("script bytes", "script", unbound)


class PointAddBuilder(ScriptBuilder):
    def __init__(self, source):
        super().__init__(source, vocabulary={"secp256k1-point-add": POINT_ADD,
                                            "rhs-from-stack": build_word("", "bytes", bytes)})

    def emit_kernel(self, name, token, site):
        kernel = KERNELS.get(name)
        if kernel is None:
            raise token.error(f"unknown kernel {name!r} at call site {site}")
        if kernel.curve != "secp256k1":
            raise token.error(f"kernel {name!r} has the wrong curve for call site {site}")
        return emit_library_kernel(self, name, kernel.library, token, site)

    def guarded_add(self, token, site):
        affine, fast = self.emit_kernel(AFFINE, token, site)
        general, fallback = self.emit_kernel(GENERAL, token, site)
        # The byte comparison proves canonical Z=1 and leaves fallback Z untouched.
        entry = asm("OP_DUP OP_1 OP_EQUAL OP_IF OP_DROP")
        otherwise = asm("OP_ELSE")
        end = asm("OP_ENDIF")
        code = entry + affine + otherwise + general + end
        guard_bytes = len(entry) + len(otherwise) + len(end)
        return code, {
            "kernel": GUARDED, "kind": "guarded-binding", "kernel_bytes": len(affine) + len(general),
            "adapter_bytes": guard_bytes, "guard_bytes": guard_bytes,
            "guard": {"argument": "rhs.z", "kind": "canonical-scriptnum-equality", "value": 1,
                      "match": {**fast, "relative_offset": len(entry)},
                      "fallback": {**fallback, "relative_offset": len(entry) + len(affine) + len(otherwise)}},
        }

    def emit_plan(self, entry, bindings):
        return emit_bound_calls(self, entry, bindings, ((POINT_ADD, self.lower_call),))

    def lower_call(self, token, site, name, encoded):
        constant = fixed_operand(encoded)
        choices = [{"kernel": kernel, "eligible": True} for kernel in (GENERAL, AFFINE, GUARDED)]
        if constant:
            choices[2].update(eligible=False, reason="the constant right operand already has a finite Z=1 proof")
        else:
            choices[1].update(eligible=False, reason="runtime right operand has no finite Z=1 proof")
        if name is None:
            name = GENERAL
        if name == GUARDED:
            if constant:
                raise token.error(f"call site {site} already has a constant right operand")
            snippet, selected = self.guarded_add(token, site)
        else:
            if name == AFFINE and not constant:
                raise token.error(f"call site {site} requires a finite right operand with proven Z=1")
            code, selected = self.emit_kernel(name, token, site)
            coords = (*constant, 1) if constant and not KERNELS[name].affine_rhs else constant
            adapter = b"".join(map(number, coords))
            snippet = adapter + code
            selected.update(adapter_bytes=len(adapter), guard_bytes=0)
        evidence = ({"kind": "checked-constant", "finite": True, "z": 1, "coordinates": encoded.hex()}
                    if constant else {"kind": "runtime-projective"})
        return snippet, {"operation": "point-add", "curve": "secp256k1", "evidence": evidence,
                         "candidates": choices, **selected}

"""Bind the same point-add operation to a compatible standard-library kernel."""

from dataclasses import dataclass
from hashlib import sha256

from fourthgraph.bsv.script import SECP256K1_FIELD as FIELD, number
from .script_builder import ScriptBuilder, build_word


@dataclass(frozen=True)
class Kernel:
    curve: str
    library: str
    affine_rhs: bool = False


GENERAL = "secp256k1-add"
AFFINE = "secp256k1-add-affine"
KERNELS = {
    GENERAL: Kernel("secp256k1", "std/secp256k1"),
    AFFINE: Kernel("secp256k1", "std/secp256k1", affine_rhs=True),
    "p256-add": Kernel("p256", "std/p256"),
}


def normalize_bindings(bindings):
    if not isinstance(bindings, list):
        raise ValueError("bindings must be an array of site and kernel pairs")
    selected = {}
    for row in bindings:
        if not isinstance(row, dict) or set(row) != {"site", "kernel"}:
            raise ValueError("each binding must have a site and kernel")
        site, kernel = row["site"], row["kernel"]
        if type(site) is not int or site < 0 or not isinstance(kernel, str):
            raise ValueError("use a nonnegative integer call site and a kernel name")
        if site in selected:
            raise ValueError(f"duplicate binding for call site {site}")
        selected[site] = kernel
    return [{"site": site, "kernel": kernel} for site, kernel in sorted(selected.items())]


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

    def emit_plan(self, entry, bindings):
        requested = {row["site"]: row["kernel"] for row in normalize_bindings(bindings)}
        sites = []

        def bind(instruction, token, args):
            if instruction is not POINT_ADD:
                return instruction.run(*args)
            prefix, encoded = args
            site = len(sites)
            constant = fixed_operand(encoded)
            choices = [{"kernel": name, "eligible": True} for name in (GENERAL, AFFINE)]
            if not constant:
                choices[1].update(eligible=False, reason="runtime right operand has no finite Z=1 proof")
            name = requested.pop(site, GENERAL)
            kernel = KERNELS.get(name)
            if kernel is None:
                raise token.error(f"unknown kernel {name!r} at call site {site}")
            if kernel.curve != "secp256k1":
                raise token.error(f"kernel {name!r} has the wrong curve for call site {site}")
            if kernel.affine_rhs and not constant:
                raise token.error(f"call site {site} requires a finite right operand with proven Z=1")
            library, _ = self.imported_words.get(name, (None, None))
            if library != kernel.library:
                raise token.error(f"call site {site} requires the bundled {kernel.library} export {name!r}")
            code = self.emit(name, b"")
            coords = constant if kernel.affine_rhs or not constant else (*constant, 1)
            adapter = b"".join(map(number, coords))
            snippet = adapter + code
            sites.append({"site": site, "source": {"module": token.module, "line": token.line, "column": token.column},
                          "operation": "point-add", "curve": kernel.curve,
                          "evidence": {"kind": "checked-constant", "finite": True, "z": 1, "coordinates": encoded.hex()}
                          if constant else {"kind": "runtime-projective"},
                          "candidates": choices, "kernel": name, "library": library,
                          "kernel_sha256": sha256(code).hexdigest(), "library_sha256": self.libraries[library].sha256,
                          "kernel_bytes": len(code), "adapter_bytes": len(adapter),
                          "offset": len(prefix), "bytes": len(snippet),
                          "linked_sha256": sha256(snippet).hexdigest()})
            return (prefix + snippet,)

        result = self.emit(entry, b"", build_call=bind)
        if requested:
            raise ValueError(f"unknown call site {min(requested)} in {entry!r}")
        return result, sites

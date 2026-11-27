"""Select kernels for fixed SHA-256 repetition regions."""

from fourthgraph.bsv.script import asm
from .call_sites import emit_bound_calls, emit_library_kernel
from .script_builder import ScriptBuilder, build_word


SINGLE = "sha256-chain-single"
PAIRS = "sha256-chain-pairs"
LIBRARY = "std/hash-chain"


def unbound(*_):
    raise ValueError("sha256-chain requires a call-site plan")


SHA256_CHAIN = build_word("script cell", "script", unbound)


class HashChainBuilder(ScriptBuilder):
    def __init__(self, source):
        super().__init__(source, vocabulary={"sha256-chain": SHA256_CHAIN})

    def emit_plan(self, entry, bindings):
        return emit_bound_calls(self, entry, SHA256_CHAIN, bindings, self.lower_call)

    def lower_call(self, token, site, name, rounds):
        if not 0 <= rounds <= 256:
            raise token.error("SHA-256 repetition must be between 0 and 256 rounds")
        if name is None:
            name = SINGLE
        if name not in (SINGLE, PAIRS):
            raise token.error(f"kernel {name!r} has the wrong operation for call site {site}")
        choices = [{"kernel": SINGLE, "eligible": True}, {"kernel": PAIRS, "eligible": rounds >= 2}]
        if rounds < 2:
            choices[1]["reason"] = "pair fusion requires at least two consecutive SHA-256 rounds"
            if name == PAIRS:
                raise token.error(choices[1]["reason"])
        count, tail = divmod(rounds, 2) if name == PAIRS else (rounds, 0)
        code, selected = emit_library_kernel(self, name, LIBRARY, token, site, count)
        adapter = asm("OP_SHA256") if tail else b""
        return code + adapter, {"operation": "sha256-chain",
                                "evidence": {"kind": "build-count", "rounds": rounds},
                                "candidates": choices, "guard_bytes": 0,
                                "adapter_bytes": len(adapter), **selected}

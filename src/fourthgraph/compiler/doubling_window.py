"""Bind fixed secp256k1 doubling windows using reduction and stack-layout evidence."""

from fourthgraph.bsv.script import asm
from .call_sites import emit_bound_calls, emit_library_kernel
from .script_builder import ScriptBuilder, build_word


LIBRARY = "std/secp256k1"
SINGLE = "secp256k1-double"
PAIRED = "secp256k1-double-pair"
LOCAL = "secp256k1-double-with-field"
LOCAL_PAIRED = "secp256k1-double-pair-with-field"
KERNELS = {SINGLE: (False, False), PAIRED: (False, True), LOCAL: (True, False), LOCAL_PAIRED: (True, True)}
BOTTOM_FIELD = asm("OP_DEPTH OP_1SUB OP_PICK")


def unbound(*_):
    raise ValueError("secp256k1-double-window requires a call-site plan")


DOUBLE_WINDOW = build_word("script cell", "script", unbound)


class DoublingWindowBuilder(ScriptBuilder):
    def __init__(self, source):
        super().__init__(source, vocabulary={"secp256k1-double-window": DOUBLE_WINDOW})

    def emit_plan(self, entry, bindings):
        return emit_bound_calls(self, entry, bindings, ((DOUBLE_WINDOW, self.lower_window),))

    def lower_window(self, token, site, name, rounds):
        if not 1 <= rounds <= 256:
            raise token.error("a doubling window must contain between 1 and 256 rounds")
        name = SINGLE if name is None else name
        if name not in KERNELS:
            raise token.error(f"kernel {name!r} has the wrong operation for call site {site}")
        local, paired = KERNELS[name]
        choices = []
        for kernel, (_, needs_pair) in KERNELS.items():
            eligible = not needs_pair or rounds >= 3
            choice = {"kernel": kernel, "eligible": eligible}
            if not eligible:
                choice["reason"] = "pairing requires a complete first round and two subsequent rounds"
                if name == kernel:
                    raise token.error(choice["reason"])
            choices.append(choice)

        prime, _ = emit_library_kernel(self, "secp256k1-field", LIBRARY, token, site)
        guard = BOTTOM_FIELD + prime + asm("OP_NUMEQUALVERIFY")
        # Keep the caller's bottom field and place a copy immediately below X,Y,Z.
        setup = BOTTOM_FIELD + asm("OP_3 OP_ROLL") * 3 if local else b""
        cleanup = asm("OP_3 OP_ROLL OP_DROP") if local else b""
        operands = (1,) if local else ()
        single = LOCAL if local else SINGLE
        pair = LOCAL_PAIRED if local else PAIRED
        pairs, tail = divmod(rounds - 1, 2) if paired else (0, 0)
        schedule = ((single, 1, 1), (pair, 2, pairs), (single, 1, tail)) if paired else ((single, 1, rounds),)
        body = bytearray()
        segments = []
        for kernel, rounds_per_copy, copies in schedule:
            if not copies:
                continue
            code, selected = emit_library_kernel(self, kernel, LIBRARY, token, site, *operands)
            segments.append({**selected, "relative_offset": len(guard) + len(setup) + len(body),
                             "rounds_per_copy": rounds_per_copy, "copies": copies})
            body.extend(code * copies)
        return guard + setup + bytes(body) + cleanup, {
            "operation": "secp256k1-double-window", "kernel": name, "candidates": choices,
            "evidence": {"kind": "fixed-window", "rounds": rounds, "checked_field": "secp256k1",
                         "field_slot": "below-point" if local else "stack-bottom",
                         "paired_input_proof": "preceding-reduction" if paired else None,
                         "paired_blocks": pairs, "complete_tail": tail},
            "segments": segments, "kernel_bytes": len(body), "guard_bytes": len(guard),
            "adapter_bytes": len(guard) + len(setup) + len(cleanup),
        }

"""Compile BIP340 with the packaged GLV lowering and the same generated point formula."""
from compare import HERE, compile_candidate
from fourthgraph.compiler.curve_lowering import joint_source, joint_vocabulary, link_joint_word
from fourthgraph.compiler.curve_windows import GLV_REFERENCE
from fourthgraph.compiler.wordsets import Primitive


def compile_window_candidate(plan, *, trace=False, linked=False, strategy=GLV_REFERENCE, joint_code=None, batch=False):
    if strategy != GLV_REFERENCE and not linked:
        raise ValueError("optimized joint lowerings require a linked word")
    def link(vocabulary, optimization):
        words = link_joint_word(vocabulary, optimization, strategy=strategy)
        if joint_code is not None:
            joint_code.append(words["secp256k1-joint-window-2"].code)
        return words

    def vocabulary(library):
        words = joint_vocabulary(library)
        if batch:
            count, width = 6, 32
            def decode(data):
                if len(data) != count * width:
                    raise ValueError("expected six 32-byte fields")
                return tuple(int.from_bytes(data[start:start + width], "big")
                             for start in range(0, count * width, width))
            words["uint256be-fields"] = Primitive(("bytes",), ("script-int",) * count,
                                                    library.emit("script-uint256be-fields", b"", count), decode,
                                                    "six fixed-width fields", may_fail=True)
        return words

    suffix = "-batch" if batch else ""
    return compile_candidate(plan, trace=trace, source=HERE / f"window-verifier{suffix}.fth", entry=f"window-bip340{suffix}",
                             extra_vocabulary=vocabulary,
                             source_prefix="" if linked else joint_source(),
                             link_vocabulary=link if linked else None)


if __name__ == "__main__":
    from compare import plans
    for plan in plans():
        if plan.name in {"source-baseline", "compiler-auto"}:
            verifier, lock, _, elapsed = compile_window_candidate(plan)
            print(plan.name, len(verifier), len(lock), round(elapsed, 2))

"""Compile BIP340 with the packaged GLV lowering and the same generated point formula."""
from compare import HERE, compile_candidate
from fourthgraph.compiler.curve_lowering import joint_source, joint_vocabulary, link_joint_word, numeric_fragment
from fourthgraph.compiler.curve_windows import GLV_REFERENCE, GLV_SCALED, SECP256K1
from fourthgraph.compiler.modular_scale import lower_affine_pair_scale, lower_scaled_residuals
from fourthgraph.compiler.wordsets import Primitive


def compile_window_candidate(plan, *, trace=False, linked=False, strategy=GLV_REFERENCE, joint_code=None, batch=False,
                             comparison="restored"):
    if strategy != GLV_REFERENCE and not linked:
        raise ValueError("optimized joint lowerings require a linked word")
    if comparison not in ("restored", "fused", "paired", "tuned"):
        raise ValueError("unknown projective comparison")
    scaled_output = comparison != "restored"
    mapped_input = comparison in ("paired", "tuned")
    if scaled_output and (strategy != GLV_SCALED or not batch):
        raise ValueError("comparison in a scaled model requires batched inputs and the scaled joint strategy")

    def link(vocabulary, optimization):
        words = link_joint_word(vocabulary, optimization, strategy=strategy, scaled_output=scaled_output,
                                mapped_input=mapped_input)
        if joint_code is not None:
            kernel, = words.values()
            joint_code.append(kernel.code)
        if scaled_output:
            model = SECP256K1.normalized_a0()
            bounds = {"coordinate_bound": model.field - 1, "scriptnum_bytes": 129}
            if mapped_input:
                transform = lower_affine_pair_scale(model.field, model.root, optimization, **bounds)
                words["map-affine-pair"] = numeric_fragment(transform, 5, 5)
            else:
                inverse = pow(model.root, -1, model.field)
                compare = lower_scaled_residuals(model.field, inverse, optimization, **bounds)
                words["scaled-nonce-residuals"] = numeric_fragment(compare, 6, 3)
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

    suffix = f"-{comparison}" if scaled_output else "-batch" if batch else ""
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

"""Compile BIP340 with the packaged GLV lowering and the same generated point formula."""
from compare import HERE, compile_candidate
from fourthgraph.compiler.curve_lowering import LayoutCompiler, joint_source, joint_vocabulary, link_joint_word


def compile_window_candidate(plan, *, trace=False, linked=False):
    return compile_candidate(plan, trace=trace, source=HERE / "window-verifier.fth", entry="window-bip340",
                             source_compiler=LayoutCompiler, extra_vocabulary=joint_vocabulary,
                             source_prefix="" if linked else joint_source(),
                             link_vocabulary=link_joint_word if linked else None)


if __name__ == "__main__":
    from compare import plans
    for plan in plans():
        if plan.name in {"source-baseline", "compiler-auto"}:
            verifier, lock, _, elapsed = compile_window_candidate(plan)
            print(plan.name, len(verifier), len(lock), round(elapsed, 2))

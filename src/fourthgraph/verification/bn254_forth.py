"""Typed construction words for a fixed-statement BN254 Forth verifier."""

from fourthgraph.compiler.source import MAX_EXPANSION, CompileError, check_word_expansion, expanded
from fourthgraph.compiler.wordsets import Primitive


PLAN_ENTRY = "bn254-emit-verified"
COMPACT_STACK_ENTRY = "bn254-emit-compact-stack"


def begin(_verifier, _signals, _owner, guard, statement):
    return ((guard, statement),)


def continue_plan(_verifier, _signals, _owner, plan):
    return (plan,)


def finish(verifier, _signals, _owner, plan):
    guard, statement = plan
    return (guard + verifier.compile_predicate(statement, fixed_msm=True, compact_statement=True,
                                               forth_plan=verifier.forth_plan),)


# Each state is a separate stack type. In particular, opening a round leaves
# a type that requires its line update and any signed residue fold to finish.
STAGES = (
    ("bn254-prime-check", "loaded", "field", "prime"),
    ("bn254-check-a", "field", "a", "curve-a"),
    ("bn254-check-c", "a", "ac", "curve-c"),
    ("bn254-check-b", "ac", "points", "curve-b"),
    ("bn254-g2-start", "points", "ladder", None),
    ("bn254-g2-double", "ladder", "ladder", ("Subgroup", 0)),
    ("bn254-g2-add-positive", "ladder", "ladder", ("Subgroup", 1)),
    ("bn254-g2-add-negative", "ladder", "ladder", ("Subgroup", -1)),
    ("bn254-g2-require-frobenius", "ladder", "subgroup", "subgroup"),
    ("bn254-bind-pairing-terms", "subgroup", "pairs", "pairs"),
    ("bn254-require-residue-inverse", "pairs", "inverse", "inverse"),
    ("bn254-miller-start", "inverse", "miller", None),
    ("bn254-miller-square", "miller", "squared", None),
    ("bn254-miller-tangent-lines", "squared", "miller", ("Miller", 0)),
    ("bn254-miller-add-positive", "miller", "positive", ("Miller", 1)),
    ("bn254-miller-add-negative", "miller", "negative", ("Miller", -1)),
    ("bn254-miller-fold-inverse", "positive", "miller", None),
    ("bn254-miller-fold-residue", "negative", "miller", None),
    ("bn254-miller-frobenius-lines", "miller", "product", "miller"),
    ("bn254-mul-fixed-residue-factor", "product", "scaled", "fixed"),
    ("bn254-mul-residue-frobenius", "scaled", "combined", "frobenius"),
    ("bn254-require-fp12-one", "combined", "checked", "identity"),
)

WORDS = {
    name: Primitive((f"bn254-{before}",), (f"bn254-{after}",), None,
                    continue_plan, "typed BN254 verifier lowering", build_only=True)
    for name, before, after, _ in STAGES
}
WORDS.update({
    "bn254-read-witness": Primitive(("bn254-authority", "bn254-statement"), ("bn254-loaded",),
                                    None, begin, "read compact BN254 witness", build_only=True),
    PLAN_ENTRY: Primitive(("bn254-checked",), ("bn254-verified",), None,
                          finish, "emit the checked BN254 verifier", build_only=True),
    COMPACT_STACK_ENTRY: Primitive(("bn254-checked",), ("bn254-verified",), None,
                                   finish, "emit with compact Script stack moves", build_only=True),
})
EVENTS = {id(WORDS[name]): event for name, _, _, event in STAGES if event is not None}
FP2 = "bn254-fp2"


def formula_only(*_args):
    raise CompileError("Fp2 operations must be defined inside a Jacobian formula word")


FP2_OPS = {}
for operation, arity in (("multiply", 2), ("subtract", 2), ("square", 1),
                         ("times-two", 1), ("times-three", 1), ("times-four", 1), ("times-eight", 1)):
    primitive = Primitive((FP2,) * arity, (FP2,), None, formula_only, "BN254 Fp2 operator", build_only=True)
    WORDS[f"bn254-fp2-{operation}"] = primitive
    FP2_OPS[id(primitive)] = operation


def lower_formula(frontend, name, inputs):
    word = frontend.words.get(name)
    if word is None or (word.takes, word.gives) != ((FP2,) * inputs, (FP2,) * 3):
        raise CompileError(f"{name} requires {inputs} Fp2 input coordinates and three outputs")
    check_word_expansion(word, MAX_EXPANSION)
    stack = list(range(inputs))
    steps = []
    for instruction, token in expanded(word.body):
        if not isinstance(instruction, Primitive) or any(kind != FP2 for kind in (*instruction.takes, *instruction.gives)):
            raise token.error("expected an Fp2 operation or typed layout in a Jacobian formula")
        start = len(stack) - len(instruction.takes)
        operands = stack[start:]
        operation = FP2_OPS.get(id(instruction))
        if operation is not None:
            stack[start:] = [inputs + len(steps)]
            steps.append({"Op": operation, "Args": operands})
        elif instruction.permutation is not None:
            stack[start:] = (operands[index] for index in instruction.permutation)
        else:
            raise token.error("expected an Fp2 operation or typed layout in a Jacobian formula")
    return {"Steps": steps, "Returns": stack}


def source_plan(frontend, instructions):
    plan = {"Stages": [], "Subgroup": [], "Miller": []}
    for instruction, token in instructions:
        event = EVENTS.get(id(instruction))
        if isinstance(event, str):
            plan["Stages"].append(event)
        elif event is not None:
            group, digit = event
            rounds = plan[group]
            if digit == 0:
                rounds.append(0)
            elif rounds and rounds[-1] == 0:
                rounds[-1] = digit
            else:
                raise token.error("a signed addition requires a fresh doubling in the same round")
    plan["Double"] = lower_formula(frontend, "bn254-jacobian-double", 3)
    plan["MixedAdd"] = lower_formula(frontend, "bn254-jacobian-mixed-add", 5)
    return plan

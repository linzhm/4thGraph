"""Compile the common fixed-generator window algorithm on registered curves."""
from dataclasses import dataclass, replace
from functools import cache
from hashlib import sha256

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, number, push
from .curve_windows import CURVES, SECP256K1, fixed_table, scalar_plans
from .lowering import compile_word
from .script_builder import ScriptBuilder
from .source import SourceCompiler, named_token
from .stack_schedule import emit_steps
from .wordsets import NATIVE_PRIMITIVES, Primitive, script_word


class LayoutCompiler(SourceCompiler):
    """Lower a layout declaration as a typed permutation of named inputs."""

    def declaration(self, token):
        if token.name != "layout:":
            return super().declaration(token)
        name = named_token(self.tokens, token, "layout name")
        terms = self.tokens.stack_effect()
        if not terms or terms.count("--") != 1 or name.name in self.words:
            raise token.error("expected a new layout name and a named stack effect")
        split = terms.index("--")
        inputs = [term.split(":") for term in terms[:split]]
        if any(len(pair) != 2 or pair[1] not in self.stack_types for pair in inputs):
            raise token.error("layout inputs require names and declared types")
        labels = {label: i for i, (label, _) in enumerate(inputs)}
        if len(labels) != len(inputs) or not all(value in labels for value in terms[split + 1:]):
            raise token.error("layout result must name an input")
        takes = tuple(kind for _, kind in inputs)
        order = tuple(labels[value] for value in terms[split + 1:])
        gives = tuple(takes[i] for i in order)
        code = emit_steps(tuple(range(len(takes))), (), order, compact=True)
        self.words[name.name] = Primitive(takes, gives, code, lambda *items: tuple(items[i] for i in order),
                                          "typed layout permutation")


def numeric_fragment(code, inputs, outputs, *, may_fail=False):
    def run(*values):
        result, _ = evaluate(code, list(map(encode_num, values)))
        return tuple(map(decode_num, result))

    return Primitive(("script-int",) * inputs, ("script-int",) * outputs, code, run,
                     "compiled numeric kernel", may_fail=may_fail)


def padded(value, width):
    encoded = bytearray(abs(value).to_bytes(width, "little"))
    if encoded[-1] & 128:
        raise ValueError("signed coordinate exceeds its fixed width")
    if value < 0:
        encoded[-1] |= 128
    return bytes(encoded)


def _shift(data, bits, *, left):
    value = int.from_bytes(data, "big")
    if left:
        value = value << bits & ((1 << (8 * len(data))) - 1)
    else:
        value >>= bits
    return value.to_bytes(len(data), "big")


def byte_vocabulary(library):
    return {
        "empty-bytes": script_word("", "bytes", b"\x00", bytes),
        "residue>bytes": script_word("script-int", "bytes", asm("33 OP_NUM2BIN"), lambda x: padded(x, 33)),
        "bytes>int": script_word("bytes", "script-int", asm("OP_BIN2NUM"), decode_num),
        "reverse-32": script_word("bytes", "bytes", library.emit("script-reverse32", b""), lambda x: x[::-1]),
        "bytes-lshift": script_word("bytes cell", "bytes", asm("OP_LSHIFT"), lambda a, b: _shift(a, b, left=True)),
        "bytes-rshift": script_word("bytes cell", "bytes", asm("OP_RSHIFT"), lambda a, b: _shift(a, b, left=False)),
        "split-at": replace(NATIVE_PRIMITIVES["op_split"], takes=("bytes", "script-int")),
    }


def projective_table(points):
    return b"".join(padded(value, 33) for point in points for value in ((0, 1, 0) if point is None else (*point, 1)))


@cache
def _kernels(curve):
    counts = {"add": 8, "double": 5}  # Extra curve parameter, p, then point coordinates.
    if curve == SECP256K1:
        library = ScriptBuilder("REQUIRE stdlib/secp256k1.fth")
        return [numeric_fragment(library.emit(f"secp256k1-{word}-with-field", b"", 1), count, 5)
                for word, count in counts.items()]
    if curve.a != -3:
        raise ValueError("this point kernel requires a curve with a = -3")
    source = SourceCompiler("REQUIRE stdlib/p256.fth")
    kernels = []
    for word, size in counts.items():
        # The P-256 kernel takes p then 3*b. Use one common parameter order for both curves.
        prefix = emit_steps(tuple(range(size)), (), (1, 0, *range(2, size)))
        suffix = emit_steps(tuple(range(5)), (), (1, 0, 2, 3, 4))
        code = compile_word(source.words[f"p256-{word}"], "stack").script
        kernels.append(numeric_fragment(prefix + code + suffix, size, 5))
    return kernels


FIXED_SOURCE = """
REQUIRE BSV
range: unsigned-scalar script-int 0 {order} ;

: first-window ( bytes -- script-int )
    1 op_split drop {right_shift} bytes-rshift bytes>int
;
: next-window ( bytes -- bytes script-int )
    dup {width} bytes-lshift swap first-window
;
: decode-point ( bytes -- script-int script-int script-int )
    33 op_split swap bytes>int swap 33 op_split swap bytes>int swap bytes>int
;
layout: expose-digit ( table:bytes scalar:bytes c:script-int p:script-int x:script-int y:script-int z:script-int --
                       table c p x y z table scalar )
layout: expose-point ( table:bytes c:script-int p:script-int x:script-int y:script-int z:script-int
                       words:bytes shifted:bytes digit:script-int -- table shifted c p x y z words digit )
layout: keep-point ( table:bytes scalar:bytes c:script-int p:script-int x:script-int y:script-int z:script-int --
                      x y z )
: step ( bytes bytes script-int script-int script-int script-int script-int --
         bytes bytes script-int script-int script-int script-int script-int )
    {doubles}
    expose-digit next-window expose-point
    99 cell>int int* split-at nip 99 op_split drop decode-point curve-add
;
: generator-multiply ( unsigned-scalar -- script-int script-int script-int )
    generator-table swap scalar>bytes reverse-32
    curve-param curve-field 0 cell>int 1 cell>int 0 cell>int
    {windows} 0 DO step LOOP
    keep-point
;
"""


@dataclass(frozen=True)
class CurveBuild:
    selected: str
    script: bytes
    candidates: tuple[dict, ...]


def _constant(name, type_name, value):
    code = push(value) if type_name == "bytes" else number(value)
    return name, script_word("", type_name, code, lambda: value)


def compile_fixed_generator(curve, mode="auto", *, optimization="stack"):
    """The Script consumes one checked scalar and returns homogeneous X, Y, Z."""
    if curve not in CURVES.values():
        raise ValueError("fixed-generator lowering requires a registered curve")
    options = [plan for plan in scalar_plans(curve) if plan.eligible]
    if mode != "auto" and mode not in {plan.name for plan in options}:
        raise ValueError("unsupported fixed-generator lowering for this curve")
    add, double = _kernels(curve)
    library = ScriptBuilder("REQUIRE stdlib/script-fragments.fth")
    vocabulary = byte_vocabulary(library) | {
        "curve-add": add, "curve-double": double,
        "scalar>bytes": script_word("script-int", "bytes", asm("33 OP_NUM2BIN 32 OP_SPLIT OP_DROP"),
                                    lambda value: value.to_bytes(32, "little")),
    }
    vocabulary.update((_constant("curve-param", "script-int", (3 * curve.b) % curve.field),
                       _constant("curve-field", "script-int", curve.field)))
    scores = []
    scripts = {}
    for plan in options:
        if mode != "auto" and plan.name != mode:
            continue
        table = projective_table(fixed_table(curve, window_bits=plan.window_bits))
        source = FIXED_SOURCE.format(order=curve.order, right_shift=8 - plan.window_bits,
                                     width=plan.window_bits, windows=plan.windows,
                                     doubles="curve-double " * plan.window_bits)
        words = vocabulary | dict((_constant("generator-table", "bytes", table),))
        frontend = LayoutCompiler(source, vocabulary=words)
        code = compile_word(frontend.words["generator-multiply"], optimization).script
        scripts[plan.name] = code
        scores.append({"algorithm": plan.name, "window_bits": plan.window_bits, "windows": plan.windows,
                       "table_bytes": len(table), "script_bytes": len(code), "sha256": sha256(code).hexdigest()})
    winner = min(scores, key=lambda row: row["script_bytes"])["algorithm"]
    return CurveBuild(winner, scripts[winner], tuple(scores))


def joint_source():
    """The packaged high-level GLV lowering. The caller links its point kernel."""
    from importlib.resources import files
    return files("fourthgraph.compiler").joinpath("secp256k1-joint.fth").read_text(encoding="utf-8")


def joint_vocabulary(library):
    from .wordsets import cell_comparison

    beta, _ = SECP256K1.endomorphism
    table = projective_table(fixed_table(SECP256K1, split_bits=128))
    vocabulary = byte_vocabulary(library) | {
        "split-glv": numeric_fragment(library.emit("secp256k1-lambda-split", b""), 1, 2),
        # DIV here only receives a bounded, nonnegative scalar and 2^128.
        "int-div": script_word("script-int script-int", "script-int", asm("OP_DIV"), lambda a, b: a // b, may_fail=True),
        "int-negate": script_word("script-int", "script-int", asm("OP_NEGATE"), lambda x: -x),
        "int-abs": script_word("script-int", "script-int", asm("OP_ABS"), abs),
        "int<": cell_comparison("script-int script-int", asm("OP_LESSTHAN"), lambda a, b: a < b),
        "int=": cell_comparison("script-int script-int", asm("OP_NUMEQUAL"), lambda a, b: a == b),
        "lane>bytes": script_word("script-int", "bytes", asm("17 OP_NUM2BIN 16 OP_SPLIT OP_DROP"),
                                  lambda x: x.to_bytes(16, "little")),
    }
    vocabulary.update((_constant("field-prime", "script-int", SECP256K1.field),
                       _constant("fixed-window-table", "bytes", table),
                       _constant("half-radix", "script-int", 1 << 128),
                       _constant("glv-beta", "script-int", beta)))
    return vocabulary


def link_joint_word(vocabulary, optimization):
    """Link the GLV word when the caller has validated its point and scalars."""
    name = "secp256k1-joint-window-2"
    frontend = LayoutCompiler(joint_source(), vocabulary=vocabulary)
    kernel = compile_word(frontend.words[name], optimization).script
    return {name: numeric_fragment(kernel, 4, 4)}


JOINT_CHECKS = """
range: joint-coordinate script-int 0 {field} ;
range: joint-scalar script-int 0 {order_plus_one} ;

layout: check-public ( x:script-int y:script-int s:script-int k:script-int p:script-int --
                       x y s k p x y )
layout: square-y ( p:script-int x:script-int y:script-int -- p x y y )
layout: cube-x ( p:script-int x:script-int yy:script-int -- p yy x x x )
: on-curve ( script-int script-int script-int -- )
    square-y int* cube-x int* int* 7 cell>int int+ int- swap int-rem
    0 cell>int int= verify
;
: joint-multiply ( joint-coordinate joint-coordinate joint-scalar joint-scalar --
                   script-int script-int script-int script-int )
    field-prime check-public on-curve secp256k1-joint-window-2
;
"""


def compile_joint_generator_point(curve, *, optimization="stack"):
    """Validate the affine point and scalars before returning p, X, Y, Z."""
    plan = next(plan for plan in scalar_plans(curve, joint=True) if plan.name == "glv-joint-window-2")
    if not plan.eligible or curve != SECP256K1:
        raise ValueError("joint GLV lowering requires secp256k1")
    library = ScriptBuilder("REQUIRE stdlib/secp256k1.fth")
    vocabulary = joint_vocabulary(library)
    vocabulary["add-points"] = numeric_fragment(library.emit("secp256k1-add-with-field", b"", 1), 7, 4)
    text = joint_source() + JOINT_CHECKS.format(field=curve.field, order_plus_one=curve.order + 1)
    frontend = LayoutCompiler(text, vocabulary=vocabulary)
    script = compile_word(frontend.words["joint-multiply"], optimization).script
    row = {"algorithm": plan.name, "window_bits": plan.window_bits, "windows": plan.windows,
           "lanes": plan.lanes, "script_bytes": len(script), "sha256": sha256(script).hexdigest()}
    return CurveBuild(plan.name, script, (row,))


def compile_curve_multiply(curve, operation, strategy="auto", *, optimization="stack"):
    if operation == "generator":
        return compile_fixed_generator(curve, strategy, optimization=optimization)
    if operation != "joint":
        raise ValueError("curve multiplication operation must be generator or joint")
    if strategy not in ("auto", "glv-joint-window-2"):
        raise ValueError("joint multiplication requires the secp256k1 GLV strategy")
    return compile_joint_generator_point(curve, optimization=optimization)


def multiplication_word(curve_name, operation, strategy):
    if curve_name not in CURVES:
        raise ValueError(f"unknown curve {curve_name!r}")
    result = compile_curve_multiply(CURVES[curve_name], operation, strategy)
    inputs, outputs = (1, 3) if operation == "generator" else (4, 4)
    return numeric_fragment(result.script, inputs, outputs, may_fail=True)

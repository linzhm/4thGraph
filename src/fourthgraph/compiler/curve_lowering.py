"""Compile the common fixed-generator window algorithm on registered curves."""
from dataclasses import dataclass, replace
from functools import cache
from hashlib import sha256

from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, number, push
from .curve_windows import CURVES, GLV_PACKED, GLV_REFERENCE, GLV_SCALED, JOINT_STRATEGIES, SECP256K1, fixed_table, scalar_plans
from .lowering import BASELINE, DATAFLOW, compile_word
from .modular_scale import lower_modular_scale
from .script_builder import ScriptBuilder
from .source import SourceCompiler
from .stack_schedule import emit_steps
from .wordsets import NATIVE_PRIMITIVES, Primitive, script_word


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
        frontend = SourceCompiler(source, vocabulary=words)
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


@cache
def packed_joint_source():
    from importlib.resources import files
    packed = files("fourthgraph.compiler").joinpath("secp256k1-joint-packed.fth").read_text(encoding="utf-8")
    return joint_source() + "\n" + packed


@cache
def stack_joint_source():
    from importlib.resources import files
    stack = files("fourthgraph.compiler").joinpath("secp256k1-joint-stack.fth").read_text(encoding="utf-8")
    return packed_joint_source() + "\n" + stack


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


@cache
def _joint_library(*, optimize=False):
    return ScriptBuilder("REQUIRE stdlib/secp256k1.fth\nREQUIRE stdlib/secp256k1-window.fth", optimize=optimize)


def _pack_windows(*lanes):
    return bytes(sum(((value >> shift) & 3) << (2 * lane) for lane, value in enumerate(lanes))
                 for shift in range(126, -1, -2))


def _optimized_joint_words(vocabulary, optimization, *, scaled):
    library = _joint_library(optimize=optimization != BASELINE)
    prefix = "secp256k1-scaled-" if scaled else "secp256k1-"
    words = vocabulary | {
        "pack-windows": script_word("script-int script-int script-int script-int", "bytes",
                                    library.emit("secp-window-pack-windows", b""), _pack_windows),
        "double-pair": numeric_fragment(library.emit(prefix + "double-pair-with-field", b"", 1), 4, 4),
        "double-point": numeric_fragment(library.emit(prefix + "double-with-field", b"", 1), 4, 4),
        "add-fixed-affine": numeric_fragment(library.emit(prefix + "add-affine-with-field", b"", 1), 6, 4),
        "map-row-coordinates": numeric_fragment(library.emit("secp-window-map-row-coordinates", b""), 11, 9),
    }
    points = fixed_table(SECP256K1, split_bits=128)
    scale_public = restore = b""
    if scaled:
        model = SECP256K1.normalized_a0()
        # Validated affine inputs and the point kernels supply reduced coordinates.
        # The 256-bit model fits a full u^3 times a coordinate in 129 bytes.
        bounds = {"coordinate_bound": model.field - 1, "scriptnum_bytes": 129}
        scale_public = lower_modular_scale(model.field, model.root, optimization, affine=True, **bounds)
        restore = lower_modular_scale(model.field, pow(model.root, -1, model.field), optimization, **bounds)
        words["add-points"] = numeric_fragment(library.emit(prefix + "add-with-field", b"", 1), 7, 4)
        points = tuple(model.affine(point) for point in points)
    words["map-affine-in-field"] = numeric_fragment(scale_public, 3, 3)
    words["restore-model"] = numeric_fragment(restore, 4, 4)
    table = b"".join(padded(coord, 33) for point in points for coord in (point or (0, 0)))
    words.update((_constant("fixed-affine-table", "bytes", table),))
    return words, points


def _variable_stack_table(frontend, words, optimization):
    """Schedule the three nonzero rows around the shared P, 2P and 3P."""
    p, px, py, qy = inputs = (0, 1, 2, 3)
    map_rows = compile_word(frontend.words["map-row-starts"], optimization).script
    row = compile_word(frontend.words["stack-table-row"], optimization).script

    def schedule(preserve_field):
        steps = []
        next_slot = len(inputs)

        def emit(code, args, count, retained=()):
            nonlocal next_slot
            outputs = tuple(range(next_slot, next_slot + count))
            steps.append((code, args, (*retained, *outputs)))
            next_slot += count
            return outputs

        one, = emit(number(1), (), 1)
        P = (px, py, one)
        retained = (p,) if preserve_field else ()
        drop = b"" if preserve_field else asm("3 OP_ROLL OP_DROP")
        P2 = emit(words["double-point"].code + drop, (p, *P), 3, retained)
        P3 = emit(words["add-fixed-affine"].code + drop, (p, *P2, px, py), 3, retained)
        starts = emit(map_rows, (p, px, *P2, *P3, qy, py), 9)
        Q, Q2, Q3 = starts[:3], starts[3:6], starts[6:]
        rows = [emit(row, (p, px, py, *point), 12) for point in (Q, Q2, Q3)]
        returns = (p, *P, *P2, *P3, *(slot for values in rows for slot in values))
        return emit_steps(inputs, steps, returns, compact=True, trim_suffix=optimization == DATAFLOW,
                          group_operands=optimization == DATAFLOW)

    plain = schedule(False)
    return min((plain, schedule(True)), key=len) if optimization == DATAFLOW else plain


def _stack_joint_script(frontend, words, points, optimization, *, scaled_output=False, mapped_input=False):
    """Compile a loop whose immutable prefix is 15 projective and 15 affine entries."""
    library = _joint_library()
    preparation = "prepare-mapped-windows" if mapped_input else "prepare-stack-windows"
    prepare = compile_word(frontend.words[preparation], optimization).script
    # The common depth encoder targets this exact stack layout. The runtime variable
    # table is in ascending order, the fixed table descending, both without index 0.
    entries = len(points) - 1
    point_slots = entries * (3 + 2)
    prepare += library.emit("secp-window-window-depths", b"") + asm("OP_TOALTSTACK")
    prepare += _variable_stack_table(frontend, words, optimization)
    prepare += b"".join(number(coordinate) for point in reversed(points[1:]) for coordinate in point)
    prepare += number(point_slots) + asm("OP_ROLL OP_0 OP_1 OP_0")

    read = library.emit("secp-window-read-window", b"")
    variable = library.emit("secp-window-pick-variable-point", b"")
    fixed = asm("OP_DUP OP_TOALTSTACK OP_PICK OP_FROMALTSTACK OP_PICK")
    fixed += words["add-fixed-affine"].code
    fixed = asm("OP_FROMALTSTACK OP_IFDUP OP_IF") + fixed + asm("OP_ENDIF")
    initial = read + asm("OP_IFDUP OP_IF") + variable + asm("OP_2ROT OP_2DROP 3 OP_ROLL OP_DROP OP_ENDIF") + fixed
    step = words["double-pair"].code + read + asm("OP_IFDUP OP_IF")
    step += variable + words["add-points"].code + asm("OP_ENDIF") + fixed
    state = tuple(range(point_slots + 4))
    cleanup = asm("OP_FROMALTSTACK OP_DROP") + emit_steps(state, (), state[point_slots:], compact=True,
                                                          trim_suffix=optimization == DATAFLOW)
    output = b"" if scaled_output else words["restore-model"].code
    return prepare + initial + step * 63 + cleanup + output


def link_joint_word(vocabulary, optimization, *, strategy=GLV_REFERENCE, scaled_output=False, mapped_input=False):
    """Link GLV for checked inputs and an explicitly declared coordinate model.

    A mapped input includes the registered field p above Px, Py, s, k. A
    scaled output returns p, X, Y, Z in the kernel's model.
    """
    name = "secp256k1-joint-window-2"
    if (scaled_output or mapped_input) and strategy != GLV_SCALED:
        raise ValueError("scaled coordinates require the scaled joint strategy")
    if mapped_input and not scaled_output:
        raise ValueError("mapped inputs use the model-preserving joint word")
    if strategy == GLV_REFERENCE:
        frontend = SourceCompiler(joint_source(), vocabulary=vocabulary)
        kernel = compile_word(frontend.words[name], optimization).script
    else:
        if strategy not in JOINT_STRATEGIES:
            raise ValueError("unknown secp256k1 joint lowering")
        words, points = _optimized_joint_words(vocabulary, optimization, scaled=strategy == GLV_SCALED)
        if strategy == GLV_PACKED:
            frontend = SourceCompiler(packed_joint_source(), vocabulary=words)
            kernel = compile_word(frontend.words["packed-joint"], optimization).script
        else:
            frontend = SourceCompiler(stack_joint_source(), vocabulary=words)
            kernel = _stack_joint_script(frontend, words, points, optimization, scaled_output=scaled_output,
                                         mapped_input=mapped_input)
    if mapped_input:
        name = "secp256k1-joint-mapped-point"
    elif scaled_output:
        name = "secp256k1-joint-scaled-point"
    return {name: numeric_fragment(kernel, 5 if mapped_input else 4, 4)}


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


def compile_joint_generator_point(curve, strategy="auto", *, optimization="stack"):
    """Validate the affine point and scalars before returning p, X, Y, Z."""
    options = [plan for plan in scalar_plans(curve, joint=True) if plan.eligible]
    if not options:
        raise ValueError("joint GLV lowering requires secp256k1")
    if strategy != "auto" and strategy not in {plan.name for plan in options}:
        raise ValueError("joint multiplication requires a secp256k1 GLV strategy")
    library = _joint_library()
    vocabulary = joint_vocabulary(library)
    vocabulary["add-points"] = numeric_fragment(library.emit("secp256k1-add-with-field", b"", 1), 7, 4)
    checks = JOINT_CHECKS.format(field=curve.field, order_plus_one=curve.order + 1)
    scores, scripts = [], {}
    for plan in options:
        if strategy != "auto" and plan.name != strategy:
            continue
        if plan.name == GLV_REFERENCE:
            frontend = SourceCompiler(joint_source() + checks, vocabulary=vocabulary)
        else:
            linked = link_joint_word(vocabulary, optimization, strategy=plan.name)
            frontend = SourceCompiler("REQUIRE BSV\n" + checks, vocabulary=vocabulary | linked)
        script = compile_word(frontend.words["joint-multiply"], optimization).script
        scripts[plan.name] = script
        scores.append({"algorithm": plan.name, "window_bits": plan.window_bits, "windows": plan.windows,
                       "lanes": plan.lanes, "script_bytes": len(script), "sha256": sha256(script).hexdigest(),
                       "coordinate_model": "a=0,3*b=1" if plan.name == GLV_SCALED else "original",
                       "table_layout": {GLV_REFERENCE: "projective-bytes", GLV_PACKED: "packed-bytes"}.get(plan.name, "stack")})
    winner = min(scores, key=lambda row: row["script_bytes"])["algorithm"]
    return CurveBuild(winner, scripts[winner], tuple(scores))


def compile_curve_multiply(curve, operation, strategy="auto", *, optimization="stack"):
    if operation == "generator":
        return compile_fixed_generator(curve, strategy, optimization=optimization)
    if operation != "joint":
        raise ValueError("curve multiplication operation must be generator or joint")
    return compile_joint_generator_point(curve, strategy, optimization=optimization)


def multiplication_word(curve_name, operation, strategy):
    if curve_name not in CURVES:
        raise ValueError(f"unknown curve {curve_name!r}")
    result = compile_curve_multiply(CURVES[curve_name], operation, strategy)
    inputs, outputs = (1, 3) if operation == "generator" else (4, 4)
    return numeric_fragment(result.script, inputs, outputs, may_fail=True)

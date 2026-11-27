"""Lower a registered scaling call once the modulus and its base are known."""
from functools import cache

from fourthgraph.bsv.script import encode_num, number

from .lowering import BASELINE, compile_word
from .script_builder import ScriptBuilder
from .source import SourceCompiler


@cache
def scale_word(name, optimization):
    library = SourceCompiler("REQUIRE stdlib/weierstrass.fth")
    return compile_word(library.words[name], optimization).script


@cache
def lower_modular_scale(modulus, root, optimization, *, affine=False, coordinate_bound=None, scriptnum_bytes=None):
    """Choose a typed scale from the same two modular-power operands.

    The caller supplies the field and any proven absolute coordinate bound. For
    a positive root, replacing its reduced powers with full powers preserves
    the sign as well as the residue of the final Script remainder.
    """
    if not 0 < root < modulus:
        raise ValueError("the scale root must be a nonzero field element")
    name = "weierstrass-scale-affine" if affine else "weierstrass-scale"
    factors = b"".join(number(pow(root, exponent, modulus)) for exponent in (2, 3))
    precomputed = factors + scale_word(name, optimization)
    if coordinate_bound is None or scriptnum_bytes is None:
        return precomputed
    if coordinate_bound < 0 or scriptnum_bytes < 1:
        raise ValueError("the coordinate and ScriptNum bounds must be nonnegative and positive respectively")
    # Before either coordinate is reduced, the largest intermediate is at most
    # u^3 times the larger of one and the maximum coordinate magnitude.
    maximum = root**3 * max(1, coordinate_bound)
    if len(encode_num(maximum)) > scriptnum_bytes:
        return precomputed
    from_root = number(root) + scale_word(name + "-root", optimization)
    return min((precomputed, from_root), key=len)


@cache
def _model_formulas():
    return ScriptBuilder("REQUIRE stdlib/weierstrass-model.fth").formula_ir


def _lower_bounded_formula(name, inputs, modulus, root, optimization, coordinate_bound, scriptnum_bytes, addend=0):
    if not 0 < root < modulus < 1 << 256:
        raise ValueError("the scale needs a nonzero root in a supported field")
    if not 0 <= coordinate_bound < 1 << 256 or scriptnum_bytes < 1:
        raise ValueError("invalid coordinate or ScriptNum bound for the model formula")

    def compile_formula(entry, operands):
        formula = _model_formulas()[entry]
        for index, value in reversed(tuple(enumerate(operands, start=inputs))):
            formula = formula.bind_input(index, value)
        return formula.lower(optimize=optimization != BASELINE)[0]

    factors = (pow(root, 2, modulus), pow(root, 3, modulus))
    maximum_factor = max(factors)
    maximum = max(modulus, coordinate_bound, maximum_factor, maximum_factor * coordinate_bound + addend)
    candidates = []
    if len(encode_num(maximum)) <= scriptnum_bytes:
        candidates.append(compile_formula(name, factors))
    maximum = max(modulus, root**3 * max(1, coordinate_bound) + addend)
    if len(encode_num(maximum)) <= scriptnum_bytes:
        candidates.append(compile_formula(name + "-root", (root,)))
    if not candidates:
        raise ValueError("no model formula is within the ScriptNum budget")
    return min(candidates, key=len)


@cache
def lower_scaled_residuals(modulus, root, optimization, *, coordinate_bound, scriptnum_bytes):
    """Lower a zero test that treats model scaling as part of the congruence.

    All coordinate magnitudes, including Z, must be at most coordinate_bound.
    The residual sign may differ from separately reducing the mapped point.
    """
    return _lower_bounded_formula("weierstrass-scaled-residuals", 6, modulus, root, optimization,
                                  coordinate_bound, scriptnum_bytes, addend=coordinate_bound**2)


@cache
def lower_affine_pair_scale(modulus, root, optimization, *, coordinate_bound, scriptnum_bytes):
    """Map two affine points with the same proven scale and field modulus."""
    return _lower_bounded_formula("weierstrass-scale-pair", 5, modulus, root, optimization,
                                  coordinate_bound, scriptnum_bytes)

"""Lower a registered scaling call once the modulus and its base are known."""
from functools import cache

from fourthgraph.bsv.script import encode_num, number

from .lowering import compile_word
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

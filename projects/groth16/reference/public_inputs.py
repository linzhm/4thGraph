"""Compute a two-limb Groth16 verification-key combination in Bitcoin Script."""

from compiler import Program
from projective import Jacobian
from verifier import Curve, Host, check_point_host

LIMB_BITS = 128
INFINITY = (0, 1, 0)


def _choose(field, condition, yes, no):
    return tuple(field.select(condition, a, b) for a, b in zip(yes, no, strict=True))


def _add_fixed(curve, jacobian, accumulator, point):
    """Complete the mixed Jacobian formula at infinity and when X coordinates match."""
    field = curve.field
    x, y, z = accumulator
    point_x, point_y = point
    z_squared = field.mul(z, z)
    dx = field.sub(field.mul(point_x, z_squared), x)
    dy = field.sub(field.mul(point_y, field.mul(z, z_squared)), y)

    mixed, _ = jacobian.add_mixed(accumulator, point)
    doubled, _ = jacobian.double(accumulator)
    same_x = _choose(field, field.nonzero(dy), INFINITY, doubled)
    finite = _choose(field, field.nonzero(dx), mixed, same_x)
    return _choose(field, field.nonzero(z), finite, jacobian.lift(point))


def verification_key_point(ic, public_inputs):
    """Affine reference for the point consumed by the pairing verifier."""
    ic0, high_base, low_base = ic
    high, low = public_inputs
    if any(type(limb) is not int or not 0 <= limb < 2**LIMB_BITS for limb in (high, low)):
        raise ValueError("expected two unsigned 128-bit public scalars")
    host = Curve(Host())
    result = host.add_host(ic0, host.mul_host(high_base, high))
    return host.add_host(result, host.mul_host(low_base, low))


def public_input_check(ic):
    """Check affine VK_x against two authenticated limbs, with (0, 0) for infinity.

    Initial stack, bottom to top: claimed y, claimed x, high limb, low limb.
    This standalone predicate leaves one truth value.
    """
    field = Program()
    low, high, claimed_x, claimed_y = (field.wire_field() for _ in range(4))
    require_public_input_point(field, ic, high, low, claimed_x, claimed_y)
    return field.compile()[0]


def require_public_input_point(field, ic, high, low, claimed_x, claimed_y):
    ic0, high_base, low_base = ic
    return require_affine_msm(
        field, ic0, ((high, high_base, LIMB_BITS), (low, low_base, LIMB_BITS)), claimed_x, claimed_y,
    )


def require_affine_msm(field, constant, terms, claimed_x, claimed_y, *, checked_offset=None):
    """Check a bounded fixed-base sum with an optional already authenticated G1 offset."""
    for point in (constant, *(base for _, base, _ in terms)):
        if point is not None:
            check_point_host(point)
    for scalar, _, width in terms:
        field.require(field.less_than(scalar, 2**width))
    curve = Curve(field)
    jacobian = Jacobian(curve)
    host = Curve(Host())
    if checked_offset is None:
        accumulator = INFINITY if constant is None else jacobian.lift(constant)
    else:
        accumulator = jacobian.lift(checked_offset)
        if constant is not None:
            accumulator = _add_fixed(curve, jacobian, accumulator, constant)
    for scalar, base, width in terms:
        if base is None:
            continue
        for bit_index in range(width):
            if bit_index == width - 1:
                bit = scalar
            else:
                quotient = field.divide(scalar, 2)
                bit = field.sub(scalar, field.mul(quotient, 2))
                scalar = quotient
            added = _add_fixed(curve, jacobian, accumulator, base)
            accumulator = _choose(field, bit, added, accumulator)
            if bit_index < width - 1:
                base = host.add_host(base, base)

    x, y, z = accumulator
    finite = field.nonzero(z)
    z_squared = field.mul(z, z)
    difference_x = field.sub(x, field.mul(claimed_x, z_squared))
    difference_y = field.sub(y, field.mul(claimed_y, field.mul(z, z_squared)))
    field.zero(field.select(finite, difference_x, claimed_x))
    field.zero(field.select(finite, difference_y, claimed_y))
    return finite


def transaction_verifier_lock(issuance_outpoint, key, *, compact_preimage=False):
    """Authenticate the spending transaction and verify a two-public-input proof."""
    from transfer import compact_verifier_binding, statement_script
    from verifier import locking_script

    body, _, _ = locking_script(
        key, None, projective_g1=True, projective_g2=True, reuse_constants=True,
    )
    prefix = statement_script(issuance_outpoint, compact_preimage=compact_preimage)
    suffix = compact_verifier_binding() if compact_preimage else b""
    return prefix + body + suffix


def transaction_verifier_unlock(statement, transaction, verifier_index, funding, key, proof):
    """Build the proof witness for the current transaction and verifier input."""
    from shared.script import push
    from verifier import unlocking_fields, unlocking_script

    inputs = statement.public_inputs(transaction, verifier_index, funding)
    point = verification_key_point(key.ic, inputs)
    coordinates = point if point is not None else (0, 0)
    proof_data = unlocking_fields(key, inputs, proof, projective_g1=True, projective_g2=True)
    preimage = statement.preimage(transaction, verifier_index, funding)
    return unlocking_script((*coordinates, *proof_data)) + push(preimage)

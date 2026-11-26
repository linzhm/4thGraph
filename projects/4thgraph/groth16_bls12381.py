"""Compile a BLS12-381 Groth16 verifier specialized by public input source."""

import argparse
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from itertools import chain
import json
from pathlib import Path

from compiler import PROJECT_NAME
from proof.bls12_381 import (
    BETA, HOST, ONE12, PSI_X, PSI_Y, Q, R, U, HostField, ScriptField, Tower,
)
from protocol import (
    FLAG, OUTPUTS_HASH, artifact_digest, authorize, begin, check_field, finish, is_compressed_public_key,
)
from shared.script import asm, number, push
from shared.transaction import Output

FIELD_BYTES = 48
PACKET_BYTES = (8 + 12) * FIELD_BYTES
SEED_BITS = bin(U)[3:]
AFFINE_BYTES = 2 * FIELD_BYTES
INFINITY = (0, 1, 0)
_FIXED_WITNESS = object()

# In Fp12*/Fp6*, f has trivial final exponentiation iff it is an R-th power.
# Q + U has gcd R with Q**6 + 1. A valid f admits nonzero z with f*z**(Q+U)
# in Fp6*. Invert the exponent on the R-th powers when constructing z.
QUOTIENT_ORDER = Q**6 + 1
RESIDUE_EXPONENT = -(pow(Q + U, -1, QUOTIENT_ORDER // R)) % (QUOTIENT_ORDER // R)


@dataclass(frozen=True)
class VerificationKey:
    alpha: tuple
    beta: tuple
    gamma: tuple
    delta: tuple
    ic: tuple


@dataclass(frozen=True)
class Proof:
    a: tuple
    b: tuple
    c: tuple


@dataclass(frozen=True)
class Dynamic:
    """An unsigned spend-time scalar, optionally restricted below Fr."""

    bits: int = R.bit_length()

    def __post_init__(self):
        if type(self.bits) is not int or not 1 <= self.bits <= R.bit_length():
            raise ValueError(f"dynamic scalar width must be in [1, {R.bit_length()}]")

    @property
    def width(self):
        return (self.bits + 7) // 8

    @property
    def limit(self):
        return min(1 << self.bits, R)


def element(value, modulus):
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= len(str(modulus)):
        value = int(value) if value == "0" or value[0] != "0" else None
    if type(value) is not int or not 0 <= value < modulus:
        raise ValueError("noncanonical BLS12-381 field element")
    return value


def document(raw):
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("protocol") != "groth16" or value.get("curve") != "bls12381":
        raise ValueError("expected a snarkjs BLS12-381 Groth16 artifact")
    return value


def g1(point, *, allow_identity=False):
    if not isinstance(point, list) or len(point) != 3:
        raise ValueError("expected a snarkjs affine G1 point")
    x, y, z = (element(coord, Q) for coord in point)
    if z == 0 and allow_identity and (x, y) == (0, 1):
        return None
    if z != 1:
        raise ValueError("expected a finite snarkjs affine G1 point")
    return x, y


def g2(point):
    if (not isinstance(point, list) or len(point) != 3
            or any(not isinstance(pair, list) or len(pair) != 2 for pair in point)):
        raise ValueError("expected a snarkjs affine G2 point")
    x, y, z = (tuple(element(coord, Q) for coord in pair) for pair in point)
    if z != (1, 0):
        raise ValueError("expected a finite snarkjs affine G2 point")
    return x, y


def read_key(raw):
    value = document(raw)
    count = value["nPublic"]
    if type(count) is not int or count < 0 or not isinstance(value["IC"], list) or len(value["IC"]) != count + 1:
        raise ValueError("verification key IC does not match its public input count")
    return VerificationKey(g1(value["vk_alpha_1"]), g2(value["vk_beta_2"]), g2(value["vk_gamma_2"]),
                           g2(value["vk_delta_2"]), tuple(g1(point, allow_identity=True) for point in value["IC"]))


def read_proof(raw):
    value = document(raw)
    return Proof(g1(value["pi_a"]), g2(value["pi_b"]), g1(value["pi_c"]))


def public_signals(raw):
    values = json.loads(raw)
    if not isinstance(values, list):
        raise ValueError("expected an array of public scalars")
    return tuple(element(value, R) for value in values)


def input_sources(raw):
    """Decode an ordered JSON array of fixed values, nulls, or bit bounds."""
    values = json.loads(raw)
    if not isinstance(values, list):
        raise ValueError("expected an array of public input sources")
    sources = []
    for value in values:
        if value is None:
            sources.append(Dynamic())
        elif isinstance(value, dict) and value.keys() == {"bits"}:
            sources.append(Dynamic(value["bits"]))
        else:
            sources.append(element(value, R))
    return tuple(sources)


def dynamic_slots(sources):
    return tuple((index, source) for index, source in enumerate(sources) if isinstance(source, Dynamic))


def public_packet(sources, signals):
    """Validate slot order and encode just the spend-time values."""
    if len(sources) != len(signals):
        raise ValueError("public signals do not match the configured input count")
    encoded = bytearray()
    for index, (source, value) in enumerate(zip(sources, signals, strict=True)):
        if type(value) is not int or not 0 <= value < R:
            raise ValueError(f"noncanonical public scalar at index {index}")
        if isinstance(source, Dynamic):
            if value >= source.limit:
                raise ValueError(f"public scalar at index {index} exceeds the configured bound")
            encoded.extend(value.to_bytes(source.width, "little"))
        elif value != source:
            raise ValueError(f"public scalar at index {index} differs from the fixed value")
    return bytes(encoded)


class Curve:
    def __init__(self, tower, *, twist=False):
        self.twist = twist
        self.tower = tower
        fp = tower.fp
        self.add, self.sub, self.mul, self.square, self.reduce, self.scale = (
            (tower.add2, tower.sub2, tower.mul2, tower.square2, tower.reduce2, tower.scale2)
            if twist else (fp.add, fp.sub, fp.mul, lambda x: fp.mul(x, x), fp.reduce, fp.mul)
        )
        self.zero, self.one, self.b = ((0, 0), (1, 0), (4, 4)) if twist else (0, 1, 4)

    def negate(self, point):
        return point[0], self.sub(self.zero, point[1])

    def equation(self, point):
        x, y = point
        return self.sub(self.square(y), self.add(self.mul(self.square(x), x), self.b))

    def double(self, point):
        x, y, z = point
        xx, yy = self.square(x), self.square(y)
        slope = self.scale(xx, 3)
        s = self.scale(self.mul(x, yy), 4)
        x3 = self.sub(self.square(slope), self.scale(s, 2))
        y3 = self.sub(self.mul(slope, self.sub(s, x3)), self.scale(self.square(yy), 8))
        z3 = self.scale(self.mul(y, z), 2)
        return (self.reduce(x3), self.reduce(y3), self.reduce(z3)), slope, yy

    def add_mixed(self, point, affine):
        x, y, z = point
        ax, ay = affine
        zz = self.square(z)
        h = self.sub(self.mul(ax, zz), x)
        slope = self.sub(self.mul(ay, self.mul(zz, z)), y)
        hh = self.square(h)
        hhh, v = self.mul(h, hh), self.mul(x, hh)
        x3 = self.sub(self.sub(self.square(slope), hhh), self.scale(v, 2))
        y3 = self.sub(self.mul(slope, self.sub(v, x3)), self.mul(y, hhh))
        return (self.reduce(x3), self.reduce(y3), self.mul(z, h)), slope

    def affine_line(self, point, other, *, doubling):
        # Precomputation and witness construction run over host field elements.
        x, y = point
        ax, ay = other
        if doubling:
            numerator, denominator = self.scale(self.square(x), 3), self.scale(y, 2)
        else:
            numerator, denominator = self.sub(ay, y), self.sub(ax, x)
        if self.twist:
            a, b = denominator
            inverse = self.scale((a, -b), pow((a*a + b*b) % Q, -1, Q))
        else:
            inverse = pow(denominator, -1, Q)
        slope = self.mul(numerator, inverse)
        x3 = self.sub(self.sub(self.square(slope), x), ax)
        y3 = self.sub(self.mul(slope, self.sub(x, x3)), y)
        return (x3, y3), (self.sub(self.mul(slope, x), y), slope)

    def add_host(self, point, other):
        if point is None:
            return other
        if other is None:
            return point
        if point[0] == other[0] and (point != other or point[1] == self.zero):
            return None
        return self.affine_line(point, other, doubling=point == other)[0]

    def mul_host(self, point, scalar):
        result = None
        for bit in bin(scalar)[2:]:
            result = self.add_host(result, result)
            if bit == "1":
                result = self.add_host(result, point)
        return result

    def require_host(self, point):
        if self.equation(point) != self.zero or self.mul_host(point, R) is not None:
            raise ValueError("point is outside the BLS12-381 prime-order subgroup")


def evaluated_line(tower, point, line):
    x, y = point
    intercept, slope = line
    return intercept, tower.scale2(slope, tower.fp.sub(0, x)), (y, 0)


def affine_lines(point):
    curve = Curve(HOST, twist=True)
    current = point
    for bit in SEED_BITS:
        current, line = curve.affine_line(current, current, doubling=True)
        lines = (line,)
        if bit == "1":
            current, line = curve.affine_line(current, point, doubling=False)
            lines += (line,)
        yield lines


def fixed_miller(point, lines):
    acc = ONE12
    for step in lines:
        acc = HOST.square12(acc)
        for line in step:
            acc = HOST.mul_line(acc, evaluated_line(HOST, point, line))
    return acc


@lru_cache(maxsize=8)
def prepare_key(key):
    g1_host, g2_host = Curve(HOST), Curve(HOST, twist=True)
    for point in (key.alpha, *key.ic):
        if point is not None:
            g1_host.require_host(point)
    for point in (key.beta, key.gamma, key.delta):
        g2_host.require_host(point)
    fixed = fixed_miller(g1_host.negate(key.alpha), affine_lines(key.beta))
    return fixed, tuple(affine_lines(key.delta)), tuple(affine_lines(key.gamma))


def fold_msm(key, sources):
    g1_host = Curve(HOST)
    vk_x = key.ic[0]
    for source, point in zip(sources, key.ic[1:], strict=True):
        if not isinstance(source, Dynamic):
            vk_x = g1_host.add_host(vk_x, g1_host.mul_host(point, source))
    return vk_x


@lru_cache(maxsize=8)
def prepare(key, signals):
    if len(key.ic) != len(signals) + 1 or any(type(x) is not int or not 0 <= x < R for x in signals):
        raise ValueError("public signals do not match the BLS12-381 verification key")
    fixed, delta, gamma = prepare_key(key)
    vk_x = fold_msm(key, signals)
    if vk_x is not None:
        fixed = HOST.mul12(fixed, fixed_miller(Curve(HOST).negate(vk_x), gamma))
    return fixed, delta


def require_affine(tower, curve, jacobian, point):
    x, y, z = jacobian
    ax, ay = point
    zz = curve.square(z)
    dx = curve.sub(x, curve.mul(ax, zz))
    dy = curve.sub(y, curve.mul(ay, curve.mul(zz, z)))
    f = tower.fp
    if curve.twist:
        f.all((f.op("OP_BOOLOR", *(f.nonzero(limb) for limb in z)),
               *(f.equal(limb, 0) for limb in chain(dx, dy))))
    else:
        f.all((f.nonzero(z), f.equal(dx, 0), f.equal(dy, 0)))


def check_g1(tower, point):
    # The BLS12-381 G1 endomorphism (x, y) -> (BETA*x, y) acts as -U² on G1.
    curve = Curve(tower)
    x, y = point
    f = tower.fp
    f.all((f.equal(curve.equation(point), 0),))
    current = (*point, 1)
    for bit in bin(U**2)[3:]:
        current, _, _ = curve.double(current)
        if bit == "1":
            current, _ = curve.add_mixed(current, point)
    require_affine(tower, curve, current, (f.mul(BETA, x), f.sub(0, y)))


def script_miller(tower, a, b, minus_c, delta, z, gamma=None):
    curve = Curve(tower, twist=True)
    f = tower.fp
    f.all(tuple(f.equal(limb, 0) for limb in curve.equation(b)))
    current = (*b, curve.one)
    acc = z
    for step, (bit, lines) in enumerate(zip(SEED_BITS, delta, strict=True)):
        acc = tower.square12(acc)
        for index, fixed in enumerate(lines):
            x, y, point_z = current
            if index == 0:
                current, slope, yy = curve.double(current)
                zz = curve.square(point_z)
                # Scale the tangent line by 2Y*Z³ in Fp2.
                intercept = curve.sub(curve.mul(slope, x), curve.scale(yy, 2))
                slope = curve.mul(slope, zz)
                factor = curve.mul(current[2], zz)
            else:
                current, slope = curve.add_mixed(current, b)
                factor = current[2]
                # Scale the chord line by H*Z in Fp2 and use its affine endpoint.
                intercept = curve.sub(curve.mul(slope, b[0]), curve.mul(factor, b[1]))
            line = intercept, tower.scale2(slope, f.sub(0, a[0])), tower.scale2(factor, a[1])
            acc = tower.mul_line(tower.mul_line(acc, line), evaluated_line(tower, minus_c, fixed))
            if gamma is not None:
                point, coefficients, finite = gamma
                gamma_line = evaluated_line(tower, point, coefficients[step][index])
                if coefficients[step][index][0] == (0, 0):
                    gamma_line = tuple(
                        tuple(f.select(finite, limb, identity) for limb, identity in zip(pair, unit, strict=True))
                        for pair, unit in zip(gamma_line, ((1, 0), (0, 0), (0, 0)), strict=True)
                    )
                # With a nonzero intercept, the enforced (0,0) encoding of
                # infinity contributes a nonzero Fp2 factor. It vanishes in
                # the Fp12*/Fp6* residue test.
                acc = tower.mul_line(acc, gamma_line)
        if bit == "1":
            acc = tower.mul12(acc, z)
    # The same loop computed [U]B. The untwisted Frobenius acts as -U on G2.
    bx, by = (tower.conjugate2(value) for value in b)
    psi = tower.mul2(bx, PSI_X), tower.scale2(tower.mul2(by, PSI_Y), -1)
    require_affine(tower, curve, current, psi)
    return acc


def unpack_packet(elements=PACKET_BYTES // FIELD_BYTES):
    decode = push(b"\x00") + asm("OP_CAT OP_BIN2NUM OP_DUP OP_0")
    take = (number(FIELD_BYTES) + asm("OP_SPLIT OP_SWAP") + decode
            + asm("OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_WITHIN OP_VERIFY OP_SWAP"))
    count = elements - 1
    return (asm("OP_SIZE") + number(elements * FIELD_BYTES) + asm("OP_NUMEQUALVERIFY")
            + number(Q) + asm("OP_TOALTSTACK") + take * count + decode
            + asm("OP_FROMALTSTACK OP_WITHIN OP_VERIFY"))


def unpack_public(slots):
    code = asm("OP_SIZE") + number(sum(source.width for _, source in slots)) + asm("OP_NUMEQUALVERIFY")
    for offset, (_, source) in enumerate(slots):
        if offset < len(slots) - 1:
            code += number(source.width) + asm("OP_SPLIT OP_SWAP")
        code += push(b"\x00") + asm("OP_CAT OP_BIN2NUM OP_DUP") + number(source.limit)
        code += asm("OP_LESSTHAN OP_VERIFY")
        if offset < len(slots) - 1:
            code += asm("OP_SWAP")
    return code


def choose_point(f, condition, yes, no):
    return tuple(f.select(condition, a, b) for a, b in zip(yes, no, strict=True))


def add_complete(curve, point, affine):
    f = curve.tower.fp
    x, y, z = point
    ax, ay = affine
    zz = f.mul(z, z)
    h = f.sub(f.mul(ax, zz), x)
    dy = f.sub(f.mul(ay, f.mul(zz, z)), y)
    (mx, my, mz), _ = curve.add_mixed(point, affine)
    mixed = mx, my, f.reduce(mz)
    doubled, _, _ = curve.double(point)
    same_x = choose_point(f, f.nonzero(dy), INFINITY, doubled)
    finite = choose_point(f, f.nonzero(h), mixed, same_x)
    return choose_point(f, f.nonzero(z), finite, (*affine, 1))


def msm_claim(tower, key, sources, values, claim):
    """Check the claimed affine VK point without an inversion in Script."""
    f, curve, host = tower.fp, Curve(tower), Curve(HOST)
    fixed = fold_msm(key, sources)
    acc = INFINITY if fixed is None else (*fixed, 1)
    for (index, source), scalar in zip(dynamic_slots(sources), values, strict=True):
        base = key.ic[index + 1]
        if base is None:
            continue
        for offset in range(0, source.bits, 2):
            remaining = source.bits - offset
            quotient = f.op("OP_DIV", scalar, 4) if remaining > 2 else 0
            digit = f.sub(scalar, f.mul(quotient, 4))
            point = base
            if remaining > 1:
                twice = host.add_host(base, base)
                thrice = host.add_host(twice, base)
                upper = f.op("OP_DIV", digit, 2)
                odd = f.sub(digit, f.mul(upper, 2))
                point = choose_point(f, upper, choose_point(f, odd, thrice, twice), base)
            added = add_complete(curve, acc, point)
            acc = choose_point(f, f.nonzero(digit), added, acc)
            scalar = quotient
            if remaining > 2:
                base = host.add_host(twice, twice)

    x, y, z = acc
    finite = f.nonzero(z)
    zz = f.mul(z, z)
    gx, gy = claim
    dx = f.sub(x, f.mul(gx, zz))
    dy = f.sub(y, f.mul(gy, f.mul(zz, z)))
    f.all((f.equal(f.select(finite, dx, gx), 0), f.equal(f.select(finite, dy, gy), 0)))
    return finite


@lru_cache(maxsize=8)
def verification_script(key, sources, *, compact=True):
    slots = dynamic_slots(sources)
    proof_elements = PACKET_BYTES // FIELD_BYTES
    if slots:
        fixed, delta, gamma_lines = prepare_key(key)
        field = ScriptField(proof_elements + 2 + len(slots))
        setup = (asm("OP_TOALTSTACK") + unpack_packet(proof_elements + 2)
                 + asm("OP_FROMALTSTACK") + unpack_public(slots))
    else:
        fixed, delta = prepare(key, sources)
        field = ScriptField(proof_elements)
        setup = unpack_packet()
    tower = Tower(field)
    a0, a1, b0, b1, b2, b3, c0, c1, *limbs = field.graph.inputs[:proof_elements]
    a, b, c = (a0, a1), ((b0, b1), (b2, b3)), (c0, c1)
    z = tuple(tuple(zip(limbs[i:i + 6:2], limbs[i + 1:i + 6:2], strict=True)) for i in (0, 6))
    gamma = None
    if slots:
        gx, gy, *values = field.graph.inputs[proof_elements:]
        finite = msm_claim(tower, key, sources, values, (gx, gy))
        gamma = (gx, field.sub(0, gy)), gamma_lines, finite
    check_g1(tower, a)
    check_g1(tower, c)
    result = script_miller(tower, a, b, Curve(tower).negate(c), delta, z, gamma)
    result = tower.mul12(tower.mul12(result, fixed), tower.frobenius12(z))
    field.all(tuple(field.equal(limb, 0) for limb in chain.from_iterable(result[1])))
    nonzero = 0
    for limb in chain.from_iterable(result[0]):
        nonzero = field.op("OP_BOOLOR", nonzero, field.nonzero(limb))
    field.all((nonzero,))
    return setup + field.compile(compact=compact and bool(slots))


def proof_packet(key, signals, proof):
    fixed, delta = prepare(key, signals)
    g1_host, g2_host = Curve(HOST), Curve(HOST, twist=True)
    g1_host.require_host(proof.a)
    g1_host.require_host(proof.c)
    g2_host.require_host(proof.b)
    minus_c = g1_host.negate(proof.c)
    acc = ONE12
    for b_step, d_step in zip(affine_lines(proof.b), delta, strict=True):
        acc = HOST.square12(acc)
        for line_b, line_delta in zip(b_step, d_step, strict=True):
            acc = HOST.mul_line(acc, evaluated_line(HOST, proof.a, line_b))
            acc = HOST.mul_line(acc, evaluated_line(HOST, minus_c, line_delta))
    product = HOST.mul12(acc, fixed)
    z = HOST.power12(product, RESIDUE_EXPONENT)
    check = HOST.mul12(product, HOST.mul12(HOST.power12(z, U), HOST.frobenius12(z)))
    if any(chain.from_iterable(check[1])) or not any(chain.from_iterable(check[0])):
        raise ValueError("Groth16 proof does not match the BLS12-381 statement")
    limbs = (*proof.a, *proof.b[0], *proof.b[1], *proof.c, *chain.from_iterable(chain.from_iterable(z)))
    return b"".join(limb.to_bytes(FIELD_BYTES, "little") for limb in limbs)


class ScriptVerifier:
    def __init__(self, verification_key):
        if isinstance(verification_key, str):
            verification_key = verification_key.encode()
        self.key = read_key(verification_key)
        self.key_digest = sha256(verification_key).hexdigest()

    def sources(self, signals):
        if signals is None:
            return (Dynamic(),) * (len(self.key.ic) - 1)
        if isinstance(signals, (str, bytes)):
            raise ValueError("expected an ordered sequence of public input sources")
        signals = tuple(signals)
        if len(signals) + 1 != len(self.key.ic):
            raise ValueError("public sources do not match the verification key")
        return tuple(source if isinstance(source, Dynamic) else Dynamic() if source is None else element(source, R)
                     for source in signals)

    def compile(self, signals=None, owner=None, *, compact=True):
        """Build the proof predicate, with optional ForkID ALL owner authorization."""
        if owner is not None and not is_compressed_public_key(owner):
            raise ValueError("owner must be a valid compressed secp256k1 public key")
        script = verification_script(self.key, self.sources(signals), compact=compact)
        return script if owner is None else authorize(owner) + script

    def witness(self, signals, proof, *, sources=_FIXED_WITNESS):
        signals = tuple(signals)
        config = self.sources(signals if sources is _FIXED_WITNESS else sources)
        public = public_packet(config, signals)
        packet = proof_packet(self.key, signals, read_proof(proof))
        if public:
            vk_x = fold_msm(self.key, signals) or (0, 0)
            packet += b"".join(coord.to_bytes(FIELD_BYTES, "little") for coord in vk_x)
            return push(packet) + push(public)
        return push(packet)

    def artifact(self, signals, owner, script, *, compact=True):
        sources = self.sources(signals)
        slots = dynamic_slots(sources)
        artifact = {
            "project": PROJECT_NAME, "schema_version": 1, "proof_system": "groth16", "curve": "bls12-381",
            "minimum_era": "genesis", "transaction_versions": [1, 2],
            "verification_key_sha256": self.key_digest,
            "script_hex": script.hex(), "script_bytes": len(script), "script_sha256": sha256(script).hexdigest(),
            "proof_packet_bytes": PACKET_BYTES,
        }
        if slots:
            artifact.update(
                schema_version=2,
                public_input_sources=tuple(
                    {"bits": source.bits} if isinstance(source, Dynamic) else str(source) for source in sources
                ),
                public_packet_bytes=sum(source.width for _, source in slots),
                proof_packet_bytes=PACKET_BYTES + AFFINE_BYTES,
                vk_claim_bytes=AFFINE_BYTES,
                stack_schedule="compact" if compact else "baseline",
            )
        else:
            artifact["public_signals"] = tuple(map(str, sources))
        if owner is not None:
            artifact.update(owner_public_key=owner.hex(), sighash=f"{FLAG:02x}")
        return {**artifact, "artifact_sha256": artifact_digest(artifact)}


def public_output(value, packet):
    """Example application state with a version byte and a canonical public packet."""
    return Output(value, push(b"\x00" + packet) + asm("OP_DROP OP_1"))


def bind_public_output(verifier_script, sources, value, versions=(1, 2)):
    """Authenticate a sole successor output built from the verifier's same public packet.

    Stack on entry: proof packet, public packet, 158-byte ForkID ALL preimage.
    The verifier is the signature-free proof predicate from ScriptVerifier.compile.
    """
    width = sum(source.width for _, source in dynamic_slots(sources))
    if not width:
        raise ValueError("public output binding needs spend-time inputs")
    suffix = asm("OP_DROP OP_1")
    prefix = public_output(value, bytes(width)).serialize()[:-(width + len(suffix))]
    return (begin(versions) + asm("OP_DUP") + push(prefix) + asm("OP_SWAP OP_CAT")
            + push(suffix) + asm("OP_CAT OP_HASH256") + check_field(OUTPUTS_HASH)
            + verifier_script + asm("OP_VERIFY") + finish())


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--verification-key", type=Path, required=True)
    cli.add_argument("--public", type=Path, help="fixed statement or actual signals for the proof witness")
    cli.add_argument("--input-sources", type=Path, help="JSON array of fixed scalars, nulls, or bit bounds")
    cli.add_argument("--stack-schedule", choices=("compact", "baseline"), default="compact",
                     help="stack scheduling for dynamic and mixed public inputs")
    cli.add_argument("--owner", help="optional compressed secp256k1 public key in hex")
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--proof", type=Path, help="snarkjs proof.json for the pinned public signals")
    cli.add_argument("--witness-output", type=Path, help="write the push-only witness prefix in hex")
    args = cli.parse_args()
    if bool(args.proof) != bool(args.witness_output):
        cli.error("--proof and --witness-output must be supplied together")
    if args.proof and not args.public:
        cli.error("--proof needs --public with the proof's full public statement")
    if args.witness_output and args.witness_output.resolve() == args.output.resolve():
        cli.error("artifact and witness need separate output paths")
    try:
        verifier = ScriptVerifier(args.verification_key.read_bytes())
        signals = public_signals(args.public.read_bytes()) if args.public else None
        sources = input_sources(args.input_sources.read_bytes()) if args.input_sources else signals
        owner = bytes.fromhex(args.owner) if args.owner is not None else None
        compact = args.stack_schedule == "compact"
        lock = verifier.compile(sources, owner, compact=compact)
        witness = verifier.witness(signals, args.proof.read_bytes(), sources=sources) if args.proof else None
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(verifier.artifact(sources, owner, lock, compact=compact), indent=2) + "\n")
        if witness is not None:
            args.witness_output.parent.mkdir(parents=True, exist_ok=True)
            args.witness_output.write_text(witness.hex() + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        cli.error(str(error))


if __name__ == "__main__":
    main()

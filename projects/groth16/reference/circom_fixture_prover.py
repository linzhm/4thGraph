"""Test-only Groth16 prover consuming a compiled Circom R1CS with two public signals."""

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from struct import unpack_from

from field import R
from fixtures import G1, G2
from verifier import Curve, Host, Proof, VerificationKey

# Public toxic waste. This proves interoperability, never protocol soundness.
ALPHA, BETA, GAMMA, DELTA, TAU = 23, 31, 37, 41, 47


def sections(path: Path, magic: bytes, version: int) -> dict[int, bytes]:
    data = path.read_bytes()
    if len(data) < 12 or data[:4] != magic:
        raise ValueError("unexpected circuit artifact")
    actual_version, count = unpack_from("<II", data, 4)
    if actual_version != version:
        raise ValueError("unsupported circuit artifact version")
    cursor = 12
    result = {}
    for _ in range(count):
        kind, length = unpack_from("<IQ", data, cursor)
        cursor += 12
        if length > len(data) - cursor or kind in result:
            raise ValueError("invalid circuit artifact section")
        result[kind] = data[cursor:cursor + length]
        cursor += length
    if cursor != len(data):
        raise ValueError("trailing circuit artifact data")
    return result


def header(data):
    width, = unpack_from("<I", data)
    if width != 32 or int.from_bytes(data[4:4 + width], "little") != R:
        raise ValueError("expected the BLS12-381 scalar field")
    return width


@dataclass(frozen=True)
class CompiledProver:
    variables: int
    rows: tuple

    @classmethod
    def load(cls, r1cs: Path):
        data = sections(r1cs, b"r1cs", 1)
        width = header(data[1])
        variables, public_outputs, public_inputs, _, _, count = unpack_from("<IIIIQI", data[1], 4 + width)
        if public_outputs + public_inputs != 2 or not 0 < count < R - 1:
            raise ValueError("expected a nonempty circuit with two public values")
        raw = data[2]
        cursor = 0
        rows = []
        for _ in range(count):
            columns = []
            for _ in range(3):
                terms, = unpack_from("<I", raw, cursor)
                cursor += 4
                if terms > variables:
                    raise ValueError("too many linear combination terms")
                combination = {}
                for _ in range(terms):
                    wire, = unpack_from("<I", raw, cursor)
                    cursor += 4
                    value = int.from_bytes(raw[cursor:cursor + width], "little")
                    cursor += width
                    if wire >= variables or wire in combination or value >= R:
                        raise ValueError("invalid linear combination")
                    combination[wire] = value
                columns.append(combination)
            rows.append(tuple(columns))
        if cursor != len(raw):
            raise ValueError("invalid R1CS constraint length")
        return cls(variables, tuple(rows))

    @cached_property
    def columns(self):
        count = len(self.rows)
        tau = TAU if count == 2 else R - 1
        prefix = [1]
        factorial = 1
        for root in range(1, count + 1):
            prefix.append(prefix[-1] * (tau - root) % R)
            factorial = factorial * root % R
        inv_factorials = [0] * (count + 1)
        inv_factorials[count] = pow(factorial, -1, R)
        for index in range(count, 0, -1):
            inv_factorials[index - 1] = inv_factorials[index] * index % R

        columns = [[0] * self.variables for _ in range(3)]
        suffix = 1
        for index in range(count - 1, -1, -1):
            right = count - index - 1
            weight = prefix[index] * suffix * inv_factorials[index] * inv_factorials[right] % R
            if right % 2:
                weight = -weight
            for target, terms in zip(columns, self.rows[index], strict=True):
                for wire, coefficient in terms.items():
                    target[wire] = (target[wire] + weight * coefficient) % R
            suffix = suffix * (tau - index - 1) % R
        return tuple(tuple(column) for column in columns)

    @cached_property
    def combined(self):
        return tuple((BETA * u + ALPHA * v + w) % R for u, v, w in zip(*self.columns, strict=True))

    @cached_property
    def key(self):
        g1, g2 = Curve(Host()), Curve(Host(), twist=True)
        inverse = pow(GAMMA, -1, R)
        return VerificationKey(
            g1.mul_host(G1, ALPHA), g2.mul_host(G2, BETA),
            g2.mul_host(G2, GAMMA), g2.mul_host(G2, DELTA),
            tuple(g1.mul_host(G1, value * inverse % R) for value in self.combined[:3]),
        )

    def prove(self, wtns: Path):
        data = sections(wtns, b"wtns", 2)
        width = header(data[1])
        count, = unpack_from("<I", data[1], 4 + width)
        if count != self.variables or len(data[2]) != count * width:
            raise ValueError("witness size does not match the circuit")
        values = tuple(
            int.from_bytes(data[2][i:i + width], "little") for i in range(0, len(data[2]), width)
        )
        if values[0] != 1 or any(value >= R for value in values):
            raise ValueError("invalid witness scalar")
        for row in self.rows:
            a, b, c = (sum(values[i] * value for i, value in col.items()) % R for col in row)
            if (a * b - c) % R:
                raise ValueError("witness does not satisfy R1CS")

        u, v, w = (sum(a * x for a, x in zip(col, values, strict=True)) % R for col in self.columns)
        # All rows hold, so the numerator vanishes on the QAP evaluation domain.
        h_times_z = (u * v - w) % R
        private_terms = sum(a * x for a, x in zip(self.combined[3:], values[3:], strict=True))
        test_r, test_s = 53, 59
        a_scalar = (ALPHA + u + test_r * DELTA) % R
        b_scalar = (BETA + v + test_s * DELTA) % R
        c_scalar = ((private_terms + h_times_z) * pow(DELTA, -1, R)
                    + test_s * a_scalar + test_r * b_scalar - test_r * test_s * DELTA) % R
        g1, g2 = Curve(Host()), Curve(Host(), twist=True)
        return values[1:3], Proof(
            g1.mul_host(G1, a_scalar), g2.mul_host(G2, b_scalar), g1.mul_host(G1, c_scalar),
        )


def export_artifacts(key, public_inputs, proof):
    """Encode the fixture artifacts using affine snarkjs JSON conventions."""
    def g1(point):
        return [str(point[0]), str(point[1]), "1"] if point is not None else ["0", "1", "0"]

    def g2(point):
        return [[str(part) for part in coefficient] for coefficient in (*point, (1, 0))]

    metadata = {"protocol": "groth16", "curve": "bls12381"}
    vk = {
        **metadata, "nPublic": len(public_inputs), "vk_alpha_1": g1(key.alpha),
        "vk_beta_2": g2(key.beta), "vk_gamma_2": g2(key.gamma), "vk_delta_2": g2(key.delta),
        "IC": [g1(point) for point in key.ic],
    }
    encoded = {**metadata, "pi_a": g1(proof.a), "pi_b": g2(proof.b), "pi_c": g1(proof.c)}
    return vk, encoded, [str(value) for value in public_inputs]

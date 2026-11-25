"""Standalone BLS12-381 Groth16 prover for standard snarkjs .zkey and .wtns."""

import argparse
import json
from functools import lru_cache
from os import open as open_fd
from dataclasses import dataclass
from os import fstat
from pathlib import Path
from secrets import randbelow
from struct import Struct, pack, unpack
from time import perf_counter

from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar

from field import Q, R
from metal_ntt import MetalNtt, powers


G1_BYTES = 96
G2_BYTES = 192
SCALAR_BYTES = 32
COEFFICIENT = Struct("<III32s")
KEY_HEADER = Struct("<I48sI32sIII")
Q_MONTGOMERY_INV = pow(1 << 384, -1, Q)
R_MONTGOMERY_SQUARED_INV = pow(1 << 512, -1, R)
# snarkjs uses the least quadratic non-residue to derive the scalar field roots.
SNARKJS_ROOT_GENERATOR = 5


def _read(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated proving artifact")
    return data


def _sections(stream, expected_magic, expected_version):
    magic, version, count = unpack("<4sII", _read(stream, 12))
    if (magic, version) != (expected_magic, expected_version):
        raise ValueError(f"expected {expected_magic.decode()} version {expected_version}")
    size = fstat(stream.fileno()).st_size
    sections = {}
    for _ in range(count):
        section, length = unpack("<IQ", _read(stream, 12))
        offset = stream.tell()
        if section in sections or length > size - offset:
            raise ValueError("invalid proving artifact section")
        sections[section] = offset, length
        stream.seek(length, 1)
    if stream.tell() != size:
        raise ValueError("trailing bytes in proving artifact")
    return sections


def _seek_section(stream, sections, section, expected_size=None):
    if section not in sections:
        raise ValueError(f"missing section {section}")
    offset, size = sections[section]
    if expected_size is not None and size != expected_size:
        raise ValueError(f"unexpected size for section {section}")
    stream.seek(offset)
    return size


def _field_element(raw, modulus):
    element = int.from_bytes(raw, "little")
    if element >= modulus:
        raise ValueError("noncanonical field element in proving artifact")
    return element


def _read_witness(path, var_count):
    with path.open("rb") as stream:
        sections = _sections(stream, b"wtns", 2)
        _seek_section(stream, sections, 1, 40)
        width, modulus, count = unpack("<I32sI", _read(stream, 40))
        if (width, int.from_bytes(modulus, "little"), count) != (SCALAR_BYTES, R, var_count):
            raise ValueError("witness field or size differs from proving key")
        _seek_section(stream, sections, 2, count * SCALAR_BYTES)
        data = _read(stream, count * SCALAR_BYTES)
    values = [_field_element(data[i:i + SCALAR_BYTES], R) for i in range(0, len(data), SCALAR_BYTES)]
    if values[0] != 1:
        raise ValueError("constant witness wire must be one")
    return values


def _read_point(stream, group, size):
    raw = _read(stream, size)
    if not any(raw):
        return group.identity()
    # zkey stores affine coordinates as little-endian Fp Montgomery residues.
    coords = (_field_element(raw[i:i + 48], Q) * Q_MONTGOMERY_INV % Q
              for i in range(0, size, 48))
    return group.from_xy_bytes_le(b"".join(value.to_bytes(48, "little") for value in coords))


def _msm(stream, group, point_size, values):
    result = group.identity()
    batch_size = 1 << 15
    for start in range(0, len(values), batch_size):
        batch = values[start:start + batch_size]
        bases = [_read_point(stream, group, point_size) for _ in batch]
        # Decoding above checks membership. The native MSM can skip rechecking it.
        result += group.multiexp_unchecked(bases, batch)
    return result


def _scalar(value):
    return Scalar.from_le_bytes(value.to_bytes(SCALAR_BYTES, "little"))


def _qap_evaluations(stream, sections, size, witness):
    section_size = _seek_section(stream, sections, 4)
    count, = unpack("<I", _read(stream, 4))
    if section_size != 4 + count * COEFFICIENT.size:
        raise ValueError("unexpected QAP coefficient table size")
    a = [0] * size
    b = [0] * size
    columns = (a, b)
    for _ in range(count):
        column, row, wire, encoded = COEFFICIENT.unpack(_read(stream, COEFFICIENT.size))
        if column >= len(columns) or row >= size or wire >= len(witness):
            raise ValueError("QAP coefficient index out of range")
        value = _field_element(encoded, R) * R_MONTGOMERY_SQUARED_INV % R
        target = columns[column]
        target[row] = (target[row] + value * witness[wire]) % R
    return a, b, [x * y % R for x, y in zip(a, b, strict=True)]


def _h_query_scalars(evaluations, transform, size):
    # Section 9 holds Lagrange-basis points at the odd roots of the 2N domain.
    coset = pow(SNARKJS_ROOT_GENERATOR, (R - 1) // (2 * size), R)
    root = coset * coset % R
    shift = powers(coset, size)

    def evaluate_on_coset(vector):
        coefficients = transform.transform(vector, root, inverse=True)
        shifted = [value * factor % R for value, factor in zip(coefficients, shift, strict=True)]
        return transform.transform(shifted, root)

    a, b, c = map(evaluate_on_coset, evaluations)
    return [_scalar((x * y - z) % R) for x, y, z in zip(a, b, c, strict=True)]


def prove_queries(alpha, beta_g1, beta, gamma, delta_g1, delta, ic, public, query, timings=None):
    """Assemble and verify a fresh plain Groth16 proof from five query MSMs."""
    r, s = _scalar(randbelow(R)), _scalar(randbelow(R))
    a = alpha + query("A") + delta_g1 * r
    b_g1 = beta_g1 + query("B1") + delta_g1 * s
    b = beta + query("B2") + delta * s
    c = query("K") + query("H") + a * s + b_g1 * r - delta_g1 * (r * s)
    verification_started = perf_counter()
    public_point = G1Point.multiexp_unchecked(ic, [_scalar(value) for value in (1, *public)])
    if not GT.pairing_check([-a, alpha, public_point, c], [b, beta, gamma, delta]):
        raise ValueError("Groth16 proof verification failed for the supplied witness and key")
    if timings is not None:
        timings["verify_seconds"] = perf_counter() - verification_started
    return {"protocol": "groth16", "curve": "bls12381", "pi_a": a.to_compressed_bytes().hex(),
            "pi_b": b.to_compressed_bytes().hex(), "pi_c": c.to_compressed_bytes().hex()}


@dataclass(frozen=True)
class ZKey:
    sections: dict
    variables: int
    public: int
    size: int
    alpha: G1Point
    beta_g1: G1Point
    beta: G2Point
    gamma: G2Point
    delta_g1: G1Point
    delta: G2Point
    ic: list

    @classmethod
    def read(cls, stream):
        sections = _sections(stream, b"zkey", 1)
        _seek_section(stream, sections, 1, 4)
        if unpack("<I", _read(stream, 4)) != (1,):
            raise ValueError("expected plain Groth16 proving key")
        _seek_section(stream, sections, 2, KEY_HEADER.size + 3 * (G1_BYTES + G2_BYTES))
        q_width, q, r_width, r, n_vars, n_public, size = KEY_HEADER.unpack(_read(stream, KEY_HEADER.size))
        widths = q_width, r_width
        moduli = int.from_bytes(q, "little"), int.from_bytes(r, "little")
        if widths != (48, SCALAR_BYTES) or moduli != (Q, R):
            raise ValueError("expected BLS12-381 proving key")
        if not 0 <= n_public < n_vars or size == 0 or size & (size - 1):
            raise ValueError("invalid Groth16 circuit dimensions")
        alpha, beta_g1 = (_read_point(stream, G1Point, G1_BYTES) for _ in range(2))
        beta, gamma = (_read_point(stream, G2Point, G2_BYTES) for _ in range(2))
        delta_g1 = _read_point(stream, G1Point, G1_BYTES)
        delta = _read_point(stream, G2Point, G2_BYTES)
        if any(point == type(point).identity() for point in (alpha, beta_g1, beta, gamma, delta_g1, delta)):
            raise ValueError("identity in Groth16 key header")
        _seek_section(stream, sections, 9, size * G1_BYTES)
        _seek_section(stream, sections, 3, (n_public + 1) * G1_BYTES)
        ic = [_read_point(stream, G1Point, G1_BYTES) for _ in range(n_public + 1)]
        return cls(sections, n_vars, n_public, size, alpha, beta_g1, beta, gamma, delta_g1, delta, ic)

    def verification_key(self):
        return {
            "protocol": "groth16", "curve": "bls12381", "nPublic": self.public,
            "vk_alpha_1": self.alpha.to_compressed_bytes().hex(),
            "vk_beta_2": self.beta.to_compressed_bytes().hex(),
            "vk_gamma_2": self.gamma.to_compressed_bytes().hex(),
            "vk_delta_2": self.delta.to_compressed_bytes().hex(),
            "IC": [point.to_compressed_bytes().hex() for point in self.ic],
        }


def prove(zkey, wtns, transform):
    """Return a verified proof, public inputs and key from standard snarkjs files."""
    started = perf_counter()
    with zkey.open("rb") as stream:
        key = ZKey.read(stream)
        witness = _read_witness(wtns, key.variables)
        private_start = key.public + 1
        scalars = [_scalar(value) for value in witness]
        h_scalars = _h_query_scalars(_qap_evaluations(stream, key.sections, key.size, witness), transform, key.size)
        queries = {
            "A": (5, G1Point, G1_BYTES, scalars),
            "B1": (6, G1Point, G1_BYTES, scalars),
            "B2": (7, G2Point, G2_BYTES, scalars),
            "K": (8, G1Point, G1_BYTES, scalars[private_start:]),
            "H": (9, G1Point, G1_BYTES, h_scalars),
        }

        def query(name):
            section, group, point_size, values = queries[name]
            _seek_section(stream, key.sections, section, point_size * len(values))
            return _msm(stream, group, point_size, values)

        public = witness[1:private_start]
        timings = {}
        proof = prove_queries(key.alpha, key.beta_g1, key.beta, key.gamma, key.delta_g1, key.delta,
                              key.ic, public, query, timings)
    timings["prove_seconds"] = perf_counter() - started
    return {"key": key.verification_key(), "proof": proof, "public_signals": list(map(str, public)), "timings": timings}


@lru_cache(maxsize=4096)
def _encode_scalar(value):
    if not 0 <= value < R:
        raise ValueError("noncanonical witness scalar")
    return value.to_bytes(SCALAR_BYTES, "little")


def write_witness(path, wires):
    """Write a standard .wtns v2 file consumable by either proving backend."""
    if not wires or wires[0] != 1:
        raise ValueError("constant witness wire must be one")
    with open(path, "xb", opener=lambda name, flags: open_fd(name, flags, 0o600)) as stream:
        stream.write(pack("<4sII", b"wtns", 2, 2))
        stream.write(pack("<IQI32sI", 1, 40, SCALAR_BYTES, R.to_bytes(SCALAR_BYTES, "little"), len(wires)))
        stream.write(pack("<IQ", 2, SCALAR_BYTES * len(wires)))
        for start in range(0, len(wires), 1 << 16):
            chunk = wires[start:start + (1 << 16)]
            stream.write(b"".join(_encode_scalar(value) for value in chunk))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("zkey", "wtns", "ntt-shader", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    artifact = prove(args.zkey, args.wtns, MetalNtt(args.ntt_shader))
    with args.out.open("x") as output:
        json.dump(artifact, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()

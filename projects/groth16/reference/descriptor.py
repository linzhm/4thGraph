"""Portable wallet descriptor and deterministic script recognition."""

from dataclasses import dataclass
from hashlib import sha256

from shared.script import asm, push

from field import Q, R
from verifier import VerificationKey, locking_script, unlocking_fields, unlocking_script

DOMAIN = b"BSV/Groth16/descriptor/v1\x00"
MARKER = push(b"BSV/Groth16/1") + asm("OP_DROP")
ID_SUFFIX = asm("OP_DROP")
PROFILES = ("separate", "fused", "alpha", "beta", "gamma")
EXPERIMENTS = ("alpha", "beta", "gamma")
DEFAULT_EXPERIMENT = "beta"
PROJECTIVE_G1_PROFILES = ("beta", "gamma")


def _encode_field(value, bound, width):
    if type(value) is not int or not 0 <= value < bound:
        raise ValueError("field element outside canonical range")
    return value.to_bytes(width, "big")


def _encode_point(point, width):
    coordinates = point if width == 2 else (*point[0], *point[1])
    if len(coordinates) != width:
        raise ValueError("incorrect coordinate count")
    return b"".join(_encode_field(coordinate, Q, 48) for coordinate in coordinates)


@dataclass(frozen=True)
class VerifierDescriptor:
    key: VerificationKey
    public_inputs: tuple
    profile: str = DEFAULT_EXPERIMENT

    def encode(self):
        key = self.key
        if len(key.ic) != len(self.public_inputs) + 1:
            raise ValueError("wrong number of IC points")
        if self.profile not in PROFILES:
            raise ValueError("unknown script profile")
        fixed_points = _encode_point(key.alpha, 2) + b"".join(
            _encode_point(point, 4) for point in (key.beta, key.gamma, key.delta)
        )
        ic = b"".join(
            b"\x00" if point is None else b"\x01" + _encode_point(point, 2)
            for point in key.ic
        )
        scalars = b"".join(_encode_field(scalar, R, 32) for scalar in self.public_inputs)
        count = len(self.public_inputs).to_bytes(4, "big")
        return DOMAIN + bytes([PROFILES.index(self.profile)]) + count + fixed_points + ic + scalars

    @classmethod
    def decode(cls, encoded):
        cursor = 0

        def take(length):
            nonlocal cursor
            value = encoded[cursor:cursor + length]
            if len(value) != length:
                raise ValueError("truncated descriptor")
            cursor += length
            return value

        def point(width):
            coords = tuple(int.from_bytes(take(48), "big") for _ in range(width))
            return coords if width == 2 else (coords[:2], coords[2:])

        if take(len(DOMAIN)) != DOMAIN:
            raise ValueError("unknown descriptor version")
        profile = take(1)[0]
        if profile >= len(PROFILES):
            raise ValueError("unknown script profile")
        count = int.from_bytes(take(4), "big")
        alpha = point(2)
        beta, gamma, delta = (point(4) for _ in range(3))
        if len(encoded) - cursor < 33 * count + 1:
            raise ValueError("truncated IC or public inputs")
        ic = []
        for _ in range(count + 1):
            tag = take(1)
            if tag not in (b"\x00", b"\x01"):
                raise ValueError("invalid IC point tag")
            ic.append(None if tag == b"\x00" else point(2))
        inputs = tuple(int.from_bytes(take(32), "big") for _ in range(count))
        result = cls(VerificationKey(alpha, beta, gamma, delta, tuple(ic)), inputs, PROFILES[profile])
        if cursor != len(encoded) or result.encode() != encoded:
            raise ValueError("noncanonical descriptor")
        return result

    def identifier(self):
        return sha256(self.encode()).digest()

    def build_lock(self):
        identifier = self.identifier()
        body, sections, _ = locking_script(
            self.key, self.public_inputs,
            fused=self.profile != "separate",
            join_lines=self.profile in EXPERIMENTS,
            projective_g1=self.profile in PROJECTIVE_G1_PROFILES,
            projective_g2=self.profile == "gamma",
            reuse_constants=self.profile in PROJECTIVE_G1_PROFILES,
        )
        prefix = MARKER + push(identifier) + ID_SUFFIX
        return prefix + body, {name: len(prefix) + offset for name, offset in sections.items()}

    def proof_fields(self, proof):
        if self.profile not in PROFILES:
            raise ValueError("unknown script profile")
        return unlocking_fields(
            self.key, self.public_inputs, proof,
            projective_g1=self.profile in PROJECTIVE_G1_PROFILES,
            projective_g2=self.profile == "gamma",
        )

    def build_unlock(self, proof):
        return unlocking_script(self.proof_fields(proof))

    def matches_lock(self, script):
        """Authenticate the entire script against this locally selected descriptor."""
        return candidate_id(script) == self.identifier() and script == self.build_lock()[0]

    def matches_prevout(self, transaction, input_index, parent):
        """Recognize the actual lock referenced by a given input."""
        if not 0 <= input_index < len(transaction.inputs):
            return False
        txin = transaction.inputs[input_index]
        return (
            0 <= txin.vout < len(parent.outputs)
            and txin.txid == parent.txid_wire()
            and self.matches_lock(parent.outputs[txin.vout].script)
        )


def candidate_id(script):
    """Recognize the discovery marker. The returned ID is untrusted."""
    start = len(MARKER)
    end = start + 33
    if script.startswith(MARKER + b"\x20") and script[end:end + 1] == ID_SUFFIX:
        return script[start + 1:end]
    return None

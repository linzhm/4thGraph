"""Byte-level P2PKH-R1 wallet operations. The input to recognition is one raw scriptPubKey."""
from functools import cache
from hashlib import new, sha256
import re

from cryptography.hazmat.primitives.asymmetric import ec

from fixed_templates import LEGACY_TEMPLATE_VERSION, TEMPLATE_VERSION, VERSIONS_DIRECTORY
from fixed_templates import compiled_owner, compiled_template


SCRIPT_SIZE = 59582
OWNER_START = 208
OWNER_END = 228
_OWNER_PATTERN = re.compile(
    rb"\x76\x00\x52\xa5\x69\x76\x6b\x7c\x82\x01.{198}(?P<owner_hash160>.{20}).{59354}",
    re.DOTALL,
)
_FIXED_HASH = bytes.fromhex("2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784")
_BASE_HASH = bytes.fromhex("b3acd6b92a23120bd24432ada2b1cac013fe06381d7ea96ac6c5a73c493f4287")


def public_key_hash160(public_key: bytes) -> bytes:
    """HASH160 over the validated 65-byte X9.63 encoding."""
    if not isinstance(public_key, bytes) or len(public_key) != 65 or public_key[0] != 4:
        raise ValueError("expected a 65-byte uncompressed P-256 public key")
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
    return new("ripemd160", sha256(public_key).digest()).digest()


@cache
def _base_program() -> bytes:
    path = VERSIONS_DIRECTORY / f"v{LEGACY_TEMPLATE_VERSION}" / "template.hex"
    raw = bytes.fromhex(path.read_text(encoding="ascii"))
    if len(raw) != SCRIPT_SIZE or sha256(raw).digest() != _BASE_HASH:
        raise ValueError("canonical P2PKH-R1 fixture mismatch")
    return raw


def locking_script_from_owner_hash(owner_hash160: bytes, *, template_version=None, compiled_curve=None) -> bytes:
    """Create v0.2.0 by default. Existing research options remain explicit."""
    if not isinstance(owner_hash160, bytes) or len(owner_hash160) != 20:
        raise ValueError("expected a 20-byte owner hash")
    if compiled_curve is not None:
        if template_version is not None:
            raise ValueError("choose either template_version or compiled_curve")
        if compiled_curve is True:
            return compiled_template().lock(owner_hash160)
        if compiled_curve is False:
            template_version = LEGACY_TEMPLATE_VERSION
        elif compiled_curve != "scheduled":
            raise ValueError("unknown curve compiler profile")
    if template_version in (None, TEMPLATE_VERSION):
        return compiled_template(scheduled=True).lock(owner_hash160)
    if template_version != LEGACY_TEMPLATE_VERSION:
        raise ValueError("unknown P2PKH-R1 template version")
    raw = _base_program()
    return raw[:OWNER_START] + owner_hash160 + raw[OWNER_END:]


def locking_script_from_public_key(public_key: bytes, *, template_version=None, compiled_curve=None) -> bytes:
    """Generate the ordinary payment script using only the recipient's R1 key."""
    return locking_script_from_owner_hash(public_key_hash160(public_key), template_version=template_version,
                                          compiled_curve=compiled_curve)


def recognize(raw: bytes) -> bytes | None:
    """Return the owner hash after checking the length and all fixed bytes."""
    if not isinstance(raw, bytes):
        return None
    if len(raw) != SCRIPT_SIZE:
        return compiled_owner(raw)
    match = _OWNER_PATTERN.fullmatch(raw)
    if match is None:
        return None
    digest = sha256(raw[:OWNER_START])
    digest.update(raw[OWNER_END:])
    if digest.digest() != _FIXED_HASH:
        return None
    return match["owner_hash160"]

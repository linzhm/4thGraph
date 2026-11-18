"""Byte-level P2PKH-R1 wallet operations. The input to recognition is one raw scriptPubKey."""
from functools import cache
from hashlib import new, sha256
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric import ec


SCRIPT_SIZE = 59706
OWNER_START = 332
OWNER_END = 352
_OWNER_PATTERN = re.compile(
    rb"\x76\x00\x52\xa5\x69\x6b\x82\x01\x20\x9d.{322}(?P<owner_hash160>.{20}).{59354}",
    re.DOTALL,
)
_FIXED_HASH = bytes.fromhex("95bebb421328f7710133c35925231673e7f3f921b31203ce0f02fe1c6825e892")
_BASE_HASH = bytes.fromhex("bef784e131b6095c604523f9b4d2d1a5af8b9eb548353f971bece7695631f9b3")


def public_key_hash160(public_key: bytes) -> bytes:
    """HASH160 over the validated 65-byte X9.63 encoding."""
    if not isinstance(public_key, bytes) or len(public_key) != 65 or public_key[0] != 4:
        raise ValueError("expected a 65-byte uncompressed P-256 public key")
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
    return new("ripemd160", sha256(public_key).digest()).digest()


@cache
def _base_program() -> bytes:
    path = Path(__file__).resolve().parents[2] / "docs/research/p2pkh-r1/template.hex"
    raw = bytes.fromhex(path.read_text(encoding="ascii"))
    if len(raw) != SCRIPT_SIZE or sha256(raw).digest() != _BASE_HASH:
        raise ValueError("canonical P2PKH-R1 fixture mismatch")
    return raw


def locking_script_from_owner_hash(owner_hash160: bytes) -> bytes:
    if not isinstance(owner_hash160, bytes) or len(owner_hash160) != 20:
        raise ValueError("expected a 20-byte owner hash")
    raw = _base_program()
    return raw[:OWNER_START] + owner_hash160 + raw[OWNER_END:]


def locking_script_from_public_key(public_key: bytes) -> bytes:
    """Generate the ordinary payment script using only the recipient's R1 key."""
    return locking_script_from_owner_hash(public_key_hash160(public_key))


def recognize(raw: bytes) -> bytes | None:
    """Return the owner hash after checking the prefix, length and all fixed bytes."""
    if not isinstance(raw, bytes) or len(raw) != SCRIPT_SIZE:
        return None
    match = _OWNER_PATTERN.fullmatch(raw)
    if match is None:
        return None
    digest = sha256(raw[:OWNER_START])
    digest.update(raw[OWNER_END:])
    if digest.digest() != _FIXED_HASH:
        return None
    return match["owner_hash160"]

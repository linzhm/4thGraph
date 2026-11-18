"""Byte-level P2PKH-R1 wallet operations. The input to recognition is one raw scriptPubKey."""
from functools import cache
from hashlib import new, sha256
from pathlib import Path
import re
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric import ec


SCRIPT_SIZE = 59811
OWNER_START = 437
OWNER_END = 457
# In script order. Each offset holds one of OP_0 and OP_1.
_POLICY = (
    (0x41, 307), (0xc1, 316), (0x42, 326), (0xc2, 336),
    (0x43, 346), (0xc3, 356), (0x61, 366), (0xe1, 376),
    (0x62, 386), (0xe2, 396), (0x63, 406), (0xe3, 416),
)
DEFAULT_TYPES = tuple(flag for flag, _ in _POLICY)
_TYPES = frozenset(DEFAULT_TYPES)
_OWNER_PATTERN = re.compile(
    rb"\x76\x00\x52\xa5\x69\x6b\x82\x01\x20\x9d.{427}(?P<owner_hash160>.{20}).{59354}",
    re.DOTALL,
)
_FIXED_HASH = bytes.fromhex("ff3a133504b7ad932bef9c3956972defeb449ed9c78450d04bda324a7c19fa03")
_BASE_HASH = bytes.fromhex("fdf704ef5eb008f6916b2b7f149f94fd410b124505cde8c0648e0710d3ed384e")
_ORDINARY_FIXED_HASH = bytes.fromhex("41c2aa447c2241e9e3c3c37da3a6b17f113a9aa2c024dc3ae62a73b8d3bdf0e8")


class PaymentParameters(NamedTuple):
    owner_hash160: bytes
    allowed_types: tuple[int, ...]


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


def locking_script_from_owner_hash(owner_hash160: bytes, allowed_types=DEFAULT_TYPES) -> bytes:
    if not isinstance(owner_hash160, bytes) or len(owner_hash160) != 20:
        raise ValueError("expected a 20-byte owner hash")
    flags = frozenset(allowed_types)
    if not flags or any(type(f) is not int for f in flags) or not flags <= _TYPES:
        raise ValueError("expected a nonempty set of supported sighash types")
    raw = bytearray(_base_program())
    raw[OWNER_START:OWNER_END] = owner_hash160
    if flags != _TYPES:
        for flag, offset in _POLICY:
            raw[offset] = 0x51 if flag in flags else 0x00
    return bytes(raw)


def locking_script_from_public_key(public_key: bytes, allowed_types=DEFAULT_TYPES) -> bytes:
    """Generate the raw scriptPubKey deterministically from an R1 public key and policy."""
    return locking_script_from_owner_hash(public_key_hash160(public_key), allowed_types)


def recognize_ordinary(raw: bytes) -> bytes | None:
    """Recognize an ordinary output, where only the 20-byte owner slot varies."""
    if not isinstance(raw, bytes) or len(raw) != SCRIPT_SIZE:
        return None
    match = _OWNER_PATTERN.fullmatch(raw)
    if match is None:
        return None
    digest = sha256(raw[:OWNER_START])
    digest.update(raw[OWNER_END:])
    if digest.digest() != _ORDINARY_FIXED_HASH:
        return None
    return match["owner_hash160"]


def recognize(raw: bytes) -> PaymentParameters | None:
    """Return the owner and policy only after all fixed program bytes are authenticated."""
    if not isinstance(raw, bytes) or len(raw) != SCRIPT_SIZE:
        return None
    match = _OWNER_PATTERN.fullmatch(raw)
    if match is None:
        return None
    digest = sha256()
    allowed = []
    start = 0
    for flag, offset in _POLICY:
        opcode = raw[offset]
        if opcode not in (0x00, 0x51):
            return None
        if opcode == 0x51:
            allowed.append(flag)
        digest.update(raw[start:offset])
        start = offset + 1
    if not allowed:
        return None
    digest.update(raw[start:OWNER_START])
    digest.update(raw[OWNER_END:])
    if digest.digest() != _FIXED_HASH:
        return None
    return PaymentParameters(match["owner_hash160"], tuple(allowed))

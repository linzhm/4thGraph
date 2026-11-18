"""Identify owner fields in canonical locking scripts. Input is the raw scriptPubKey."""
from dataclasses import dataclass
from hashlib import new, sha256
import re

from cryptography.hazmat.primitives.asymmetric import ec

from handwritten import match_locking_script
import p2pkh_r1


# Call fullmatch on bytes. Push lengths and all opcodes outside each capture are fixed.
_P2PKH = re.compile(rb"\x76\xa9\x14(?P<owner_hash160>.{20})\x88\xac", re.DOTALL)
_P2PK = re.compile(rb"(?:\x21(?P<compressed>[\x02\x03].{32})|\x41(?P<uncompressed>\x04.{64}))\xac", re.DOTALL)
_SEC1 = re.compile(rb"(?:[\x02\x03].{32}|\x04.{64})", re.DOTALL)


@dataclass(frozen=True)
class LockIdentity:
    script_type: str
    curve: str
    owner_hash160: bytes | None = None
    owner_public_key: bytes | None = None
    template_version: int | None = None
    allowed_types: tuple[int, ...] = ()


def _valid_public_key(key, curve):
    if not isinstance(key, bytes) or _SEC1.fullmatch(key) is None:
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(curve, key)
    except ValueError:
        return False
    return True


def identify_locking_script(raw: bytes) -> LockIdentity | None:
    """Return public owner fields only. Unrecognized inputs are never echoed."""
    if not isinstance(raw, bytes):
        return None
    if len(raw) <= 67:
        match = _P2PKH.fullmatch(raw)
        if match:
            return LockIdentity("P2PKH", "secp256k1", owner_hash160=match["owner_hash160"])
        match = _P2PK.fullmatch(raw)
        if match:
            key = match["compressed"] or match["uncompressed"]
            if _valid_public_key(key, ec.SECP256K1()):
                return LockIdentity("P2PK", "secp256k1", owner_public_key=key)
        return None

    if len(raw) == p2pkh_r1.SCRIPT_SIZE:
        payment = p2pkh_r1.recognize(raw)
        if payment is None:
            return None
        return LockIdentity("P2PKH-R1", "secp256r1", owner_hash160=payment.owner_hash160,
                            template_version=7, allowed_types=payment.allowed_types)

    # Match the exact R1 program (including its fixed verifier suffix) before
    # extracting its parameter slots. Embedded curve constants have no owner role.
    payment = match_locking_script(raw)
    if payment is None:
        return None
    return LockIdentity(payment.template_name, "secp256r1", owner_hash160=payment.owner_hash160,
                        template_version=payment.version, allowed_types=payment.allowed_types)


def matches_owner_key(lock: LockIdentity, public_key: bytes) -> bool:
    """Check a separately supplied public key against this owner's exact encoding."""
    if lock.script_type == "P2PKH-R1":
        if not isinstance(public_key, bytes) or public_key[:1] != b"\x04":
            return False
        curve = ec.SECP256R1()
    elif lock.script_type in ("P2PK", "P2PKH"):
        curve = ec.SECP256K1()
    else:
        return False
    if not _valid_public_key(public_key, curve):
        return False
    if lock.script_type == "P2PK":
        return public_key == lock.owner_public_key
    return new("ripemd160", sha256(public_key).digest()).digest() == lock.owner_hash160

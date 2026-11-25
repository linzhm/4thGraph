"""External secp256k1 signer adapter for native P2PK and P2PKH."""
from hashlib import new, sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from shared.pushtx import N
from shared.script import push
from shared.transaction import CHRONICLE, SIGHASH_SINGLE, hash256, preimage_forkid, preimage_otda


def _key(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 33 or public_key[0] not in (2, 3):
        raise ValueError("expected a compressed secp256k1 public key")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)


def lock(public_key, profile):
    _key(public_key)
    if profile == "p2pk":
        return push(public_key) + b"\xac"
    if profile not in (None, "p2pkh"):
        raise ValueError("expected p2pk or p2pkh")
    owner = new("ripemd160", sha256(public_key).digest()).digest()
    return lock_owner(owner)


def lock_owner(owner):
    if len(owner) != 20:
        raise ValueError("expected a 20-byte owner hash")
    return b"\x76\xa9" + push(owner) + b"\x88\xac"


def recognize(script, public_key):
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        if public_key is None or script == lock(public_key, "p2pkh"):
            return {"template": "p2pkh", "ownerHash160": script[3:23].hex()}
    if len(script) == 35 and script[0] == 33 and script[-1] == 0xac:
        try:
            _key(script[1:34])
        except ValueError:
            return None
        if public_key is None or script[1:34] == public_key:
            return {"template": "p2pk"}
    return None


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    from shared.transaction import Transaction

    key = _key(public_key)
    previous = Transaction.parse(funding_raw).outputs[tx.inputs[index].vout]
    recognized = recognize(previous.script, public_key)
    if recognized is None:
        raise ValueError("funding output does not match the native key")
    if sighash & 31 == SIGHASH_SINGLE and index >= len(tx.outputs):
        raise ValueError("native wallet requires a same-index output for SINGLE")
    if sighash & CHRONICLE:
        preimage = preimage_otda(tx, index, previous.script, sighash)
    else:
        preimage = preimage_forkid(tx, index, previous.value, previous.script, sighash)
    digest = hash256(preimage)
    signature = signer(digest)
    r, s = utils.decode_dss_signature(signature)
    if not (0 < r < N and 0 < s <= N // 2):
        raise ValueError("expected a low-S DER secp256k1 signature")
    try:
        key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature as error:
        raise ValueError("invalid native signature") from error
    script = push(signature + bytes([sighash]))
    if recognized["template"] == "p2pkh":
        script += push(public_key)
    return tx.with_script(index, script)

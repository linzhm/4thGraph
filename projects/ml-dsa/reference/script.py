"""Pure ML-DSA-44 Script verifier and BSV payment binding."""

from hashlib import shake_256

from challenge_script import sample_in_ball_script
from fips204 import CHALLENGE_BYTES, PUBLIC_KEY_BYTES
from hint_script import apply_hints_script
from mldsa import DIGEST_BYTES
from ntt_script import verification_equation_script
from shake_script import shake256_script
from signature_script import signature_decode_script
from fourthgraph.bsv.pushtx import authorization_checks, check_binding
from fourthgraph.bsv.script import asm, number, push

# The ordinary and companion scriptCode suffixes distinguish ML-DSA from the
# Lamport, WOTS+ and SLH-DSA templates.
_TAG = asm("OP_NOP OP_NOP OP_NOP")
ORDINARY_CODE = _TAG + asm("OP_ENDIF OP_CHECKSIG")
COMPANION_CODE = _TAG + asm("OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR") + ORDINARY_CODE


def verify_message_script(public_key, message_bytes, *, context=b""):
    """Compile a verifier that consumes the message and signature from the stack."""
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("ML-DSA-44 public key must be 1,312 bytes")
    if not isinstance(context, bytes) or len(context) > 255:
        raise ValueError("ML-DSA context must be at most 255 bytes")
    if type(message_bytes) is not int or message_bytes < 0:
        raise ValueError("ML-DSA message length must be a nonnegative integer")

    code = bytearray(asm("OP_OVER OP_SIZE") + number(message_bytes) + asm("OP_NUMEQUALVERIFY OP_DROP"))
    code += signature_decode_script()
    # [message, c_tilde, z, hints] -> [message, c_tilde, c || z].
    code += asm("OP_TOALTSTACK OP_OVER") + sample_in_ball_script()
    code += asm("OP_SWAP OP_CAT") + verification_equation_script(public_key)
    code += asm("OP_FROMALTSTACK") + apply_hints_script()

    # Compute mu from the approved message and append the reconstructed w1.
    prefix = shake_256(public_key).digest(64) + bytes((0, len(context))) + context
    code += asm("OP_TOALTSTACK OP_TOALTSTACK") + push(prefix) + asm("OP_SWAP OP_CAT")
    code += shake256_script(len(prefix) + message_bytes, 64)
    code += asm("OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK OP_CAT")
    code += shake256_script(64 + 768, CHALLENGE_BYTES)
    return bytes(code) + asm("OP_EQUAL")


def locking_script(public_key):
    """Bind the Pure ML-DSA-44 verifier to the current transaction input."""
    verifier = verify_message_script(public_key, DIGEST_BYTES)
    code = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    code += asm("OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK OP_SWAP")
    code += verifier + asm("OP_VERIFY OP_FROMALTSTACK")
    return code + check_binding(COMPANION_CODE)

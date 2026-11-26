"""Pure ML-DSA-44 Script verifier and BSV payment binding."""

from enum import IntEnum
from hashlib import shake_256
from pathlib import Path

from challenge_script import sample_in_ball_script
from fips204 import CHALLENGE_BYTES, PUBLIC_KEY_BYTES
from hint_script import apply_hints_script, apply_sparse_hints_script
from mldsa import DIGEST_BYTES
from ntt_script import checked_equation_script, verification_equation_script
from shake_script import shake256_script
from signature_script import signature_decode_script
from fourthgraph.bsv.pushtx import authorization_checks, check_binding
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.compiler.wordsets import Primitive

# The ordinary and companion scriptCode suffixes distinguish ML-DSA from the
# Lamport, WOTS+ and SLH-DSA templates.
_TAG = asm("OP_NOP OP_NOP OP_NOP")
ORDINARY_CODE = _TAG + asm("OP_ENDIF OP_CHECKSIG")
COMPANION_CODE = _TAG + asm("OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR") + ORDINARY_CODE
_PAYMENT_SOURCE = Path(__file__).with_name("payment-lock.fth")


class _VerifierVersion(IntEnum):
    ORIGINAL = 0
    COMPACT = 1
    V02 = 2
    V03 = 3
    V04 = 4
    V05 = 5
    V06 = 6


def _shake_options(version):
    return {
        "compact": version >= _VerifierVersion.COMPACT,
        "optimize": version >= _VerifierVersion.V02,
        "packed_rows": version >= _VerifierVersion.V05,
        "packed_state": version >= _VerifierVersion.V06,
    }


def verify_message_script(public_key, message_bytes, *, context=b"", legacy=False):
    """Compile a verifier that consumes the message and signature from the stack."""
    version = _VerifierVersion.ORIGINAL if legacy else _VerifierVersion.V06
    challenges = _reconstruct_challenge(public_key, message_bytes, context=context, version=version)
    return challenges + asm("OP_EQUAL")


def _reconstruct_challenge(public_key, message_bytes, *, context=b"", version):
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("ML-DSA-44 public key must be 1,312 bytes")
    if not isinstance(context, bytes) or len(context) > 255:
        raise ValueError("ML-DSA context must be at most 255 bytes")
    if type(message_bytes) is not int or message_bytes < 0:
        raise ValueError("ML-DSA message length must be a nonnegative integer")

    shake = _shake_options(version)
    compact = shake["compact"]
    signed = version >= _VerifierVersion.V02
    sparse_hints = version >= _VerifierVersion.V04
    code = bytearray(asm("OP_OVER OP_SIZE") + number(message_bytes) + asm("OP_NUMEQUALVERIFY OP_DROP"))
    code += signature_decode_script(compact=compact, signed_response=signed, sparse_hints=sparse_hints)
    # [message, c_tilde, z, hints] -> [message, c_tilde, c || z].
    code += asm("OP_TOALTSTACK OP_OVER") + sample_in_ball_script(**shake)
    if signed:
        equation = checked_equation_script(public_key, packed=version >= _VerifierVersion.V03,
                                           paired=version >= _VerifierVersion.V06)
    else:
        equation = verification_equation_script(public_key, compact=compact)
    code += asm("OP_SWAP OP_CAT") + equation
    code += asm("OP_FROMALTSTACK")
    code += apply_sparse_hints_script() if sparse_hints else apply_hints_script(compact=compact)

    # Compute mu from the approved message and append the reconstructed w1.
    prefix = shake_256(public_key).digest(64) + bytes((0, len(context))) + context
    code += asm("OP_TOALTSTACK OP_TOALTSTACK") + push(prefix) + asm("OP_SWAP OP_CAT")
    code += shake256_script(len(prefix) + message_bytes, 64, **shake)
    code += asm("OP_FROMALTSTACK OP_SWAP OP_FROMALTSTACK OP_CAT")
    code += shake256_script(64 + 768, CHALLENGE_BYTES, **shake)
    return bytes(code)


def locking_script(public_key, *, legacy=False):
    """Bind the Pure ML-DSA-44 verifier to the current transaction input."""
    if legacy:
        return _historical_lock(public_key, compact=False)
    challenges = _reconstruct_challenge(public_key, DIGEST_BYTES, version=_VerifierVersion.V06)
    return _compile_payment_lock(challenges, compact_binding=True)


def _runtime_fragment(takes, gives, code):
    def run(*_):
        raise ValueError("this fragment must run in a Bitcoin Script interpreter")

    return Primitive(tuple(takes.split()), tuple(gives.split()), code, run, "Script runtime", may_fail=True)


def _compile_payment_lock(challenges, *, compact_binding=False):
    vocabulary = {
        "check-authorization": _runtime_fragment(
            "bytes bytes bytes", "bytes bytes", authorization_checks(ORDINARY_CODE, COMPANION_CODE)),
        "reconstruct-challenge": _runtime_fragment("bytes bytes", "bytes bytes", challenges),
        "bind-input": _runtime_fragment("bytes", "cell", check_binding(COMPANION_CODE, compact=compact_binding)),
    }
    frontend = SourceCompiler(_PAYMENT_SOURCE.read_text(encoding="ascii"), vocabulary=vocabulary,
                              source_path=_PAYMENT_SOURCE)
    return compile_word(frontend.words["ml-dsa-payment-lock"], "stack", spend_entry=True).script


def _historical_lock(public_key, *, compact):
    version = _VerifierVersion.COMPACT if compact else _VerifierVersion.ORIGINAL
    challenges = _reconstruct_challenge(public_key, DIGEST_BYTES, version=version)
    code = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    code += asm("OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK OP_SWAP")
    code += challenges + asm("OP_EQUAL OP_VERIFY OP_FROMALTSTACK")
    return code + check_binding(COMPANION_CODE)


def _historical_forth_lock(public_key, *, version):
    challenges = _reconstruct_challenge(public_key, DIGEST_BYTES, version=version)
    # The historical Forth locks share this emitted digest and verifier wrapper.
    code = authorization_checks(ORDINARY_CODE, COMPANION_CODE)
    code += asm("OP_SWAP OP_HASH256 OP_DUP OP_ROT")
    binding = check_binding(COMPANION_CODE, compact=version >= _VerifierVersion.V05)
    return code + challenges + asm("OP_EQUALVERIFY") + binding


def matches_lock(script, public_key):
    """Match any supported generation of the fixed-key payment template."""
    return (script == locking_script(public_key)
            or any(script == _historical_forth_lock(public_key, version=version)
                   for version in (_VerifierVersion.V05, _VerifierVersion.V04,
                                   _VerifierVersion.V03, _VerifierVersion.V02))
            or script == _historical_lock(public_key, compact=True)
            or script == _historical_lock(public_key, compact=False))

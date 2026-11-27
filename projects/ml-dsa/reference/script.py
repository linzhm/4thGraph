"""Pure ML-DSA-44 Script verifier and BSV payment binding."""

from enum import IntEnum
from hashlib import shake_256
from pathlib import Path

from challenge_script import sample_in_ball_script
from fips204 import CHALLENGE_BYTES, PUBLIC_KEY_BYTES
from hint_script import (
    apply_hints_before_rounding_script, apply_hints_script, apply_hints_with_packed_rounding_script,
    apply_sparse_hints_script,
)
from mldsa import DIGEST_BYTES
from ntt_script import checked_equation_script, packed_response_equation_script, verification_equation_script
from shake_script import shake256_script
from signature_script import signature_decode_script
from fourthgraph.bsv.pushtx import authorization_checks, check_binding
from fourthgraph.bsv.script import asm, number, push
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.script_builder import ScriptBuilder, build_word
from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.compiler.wordsets import Primitive

# The ordinary and companion scriptCode suffixes distinguish ML-DSA from the
# Lamport, WOTS+ and SLH-DSA templates.
_TAG = asm("OP_NOP OP_NOP OP_NOP")
ORDINARY_CODE = _TAG + asm("OP_ENDIF OP_CHECKSIG")
COMPANION_CODE = _TAG + asm("OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR") + ORDINARY_CODE
_FORTH = Path(__file__).resolve().parents[1] / "forth"
_PAYMENT_SOURCE = _FORTH / "payment-lock.fth"
_CHALLENGE_SOURCE = _FORTH / "challenge.fth"


class _VerifierVersion(IntEnum):
    ORIGINAL = 0
    COMPACT = 1
    V02 = 2
    V03 = 3
    V04 = 4
    V05 = 5
    V06 = 6
    V07 = 7
    V08 = 8
    V09 = 9
    V10 = 10
    V11 = 11


def _shake_options(version):
    return {
        "compact": version >= _VerifierVersion.COMPACT,
        "optimize": version >= _VerifierVersion.V02,
        "packed_rows": version >= _VerifierVersion.V05,
        "packed_state": version >= _VerifierVersion.V06,
        "stream_rows": version >= _VerifierVersion.V07,
        "vector_bytes": version >= _VerifierVersion.V10,
        "direct_absorb": version >= _VerifierVersion.V11,
    }


def _hints_script(version):
    if version >= _VerifierVersion.V09:
        return apply_hints_with_packed_rounding_script()
    if version >= _VerifierVersion.V07:
        return apply_hints_before_rounding_script()
    if version >= _VerifierVersion.V04:
        return apply_sparse_hints_script()
    return apply_hints_script(compact=version >= _VerifierVersion.COMPACT)


def verify_message_script(public_key, message_bytes, *, context=b"", legacy=False):
    """Compile a verifier that consumes the message and signature from the stack."""
    if legacy:
        challenges = _reconstruct_challenge(
            public_key, message_bytes, context=context, version=_VerifierVersion.ORIGINAL,
        )
        return challenges + asm("OP_EQUAL")
    return _challenge_builder(public_key, message_bytes, context).emit("ml-dsa-verify-message", b"")


def _validate_challenge_inputs(public_key, message_bytes, context):
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("ML-DSA-44 public key must be 1,312 bytes")
    if not isinstance(context, bytes) or len(context) > 255:
        raise ValueError("ML-DSA context must be at most 255 bytes")
    if type(message_bytes) is not int or message_bytes < 0:
        raise ValueError("ML-DSA message length must be a nonnegative integer")


def _challenge_builder(public_key, message_bytes, context=b""):
    _validate_challenge_inputs(public_key, message_bytes, context)
    shake = _shake_options(_VerifierVersion.V11)
    prefix = shake_256(public_key).digest(64) + bytes((0, len(context))) + context
    kernels = {
        "ml-dsa-decode-signature": signature_decode_script(
            compact=True, signed_response=True, sparse_hints=True, packed_response=True,
        ),
        "ml-dsa-sample-challenge": sample_in_ball_script(**shake, signed=True, search=True, find_by_borrow=True),
        "ml-dsa-verify-equation": packed_response_equation_script(public_key, compact_packing=True),
        "ml-dsa-apply-hints": _hints_script(_VerifierVersion.V11),
        "ml-dsa-hash-mu": shake256_script(len(prefix) + message_bytes, 64, **shake),
        "ml-dsa-hash-challenge": shake256_script(64 + 768, CHALLENGE_BYTES, **shake),
    }
    vocabulary = {
        name: build_word("script", "script", lambda code, kernel=kernel: code + kernel)
        for name, kernel in kernels.items()
    }
    vocabulary.update({
        "ml-dsa-message-bytes": build_word("", "cell", lambda: message_bytes),
        "ml-dsa-mu-prefix": build_word("", "bytes", lambda: prefix),
    })
    return ScriptBuilder.from_file(_CHALLENGE_SOURCE, vocabulary=vocabulary)


def _reconstruct_challenge(public_key, message_bytes, *, context=b"", version):
    _validate_challenge_inputs(public_key, message_bytes, context)
    shake = _shake_options(version)
    compact = shake["compact"]
    signed = version >= _VerifierVersion.V02
    sparse_hints = version >= _VerifierVersion.V04
    signed_challenge = version >= _VerifierVersion.V07
    packed_response = version >= _VerifierVersion.V08
    code = bytearray(asm("OP_OVER OP_SIZE") + number(message_bytes) + asm("OP_NUMEQUALVERIFY OP_DROP"))
    code += signature_decode_script(compact=compact, signed_response=signed, sparse_hints=sparse_hints,
                                    packed_response=packed_response)
    # [message, c_tilde, z, hints] -> [message, c_tilde, c || z].
    code += asm("OP_TOALTSTACK OP_OVER") + sample_in_ball_script(
        **shake, signed=signed_challenge, search=version >= _VerifierVersion.V10,
        find_by_borrow=version >= _VerifierVersion.V11,
    )
    if packed_response:
        equation = packed_response_equation_script(public_key, compact_packing=version >= _VerifierVersion.V09)
    elif signed:
        equation = checked_equation_script(public_key, packed=version >= _VerifierVersion.V03,
                                           paired=version >= _VerifierVersion.V06,
                                           signed_challenge=signed_challenge)
    else:
        equation = verification_equation_script(public_key, compact=compact)
    code += asm("OP_SWAP OP_CAT") + equation
    code += asm("OP_FROMALTSTACK")
    code += _hints_script(version)

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
    challenges = _challenge_builder(public_key, DIGEST_BYTES).emit("ml-dsa-challenge", b"")
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
                   for version in (_VerifierVersion.V10, _VerifierVersion.V09, _VerifierVersion.V08,
                                   _VerifierVersion.V07, _VerifierVersion.V06,
                                   _VerifierVersion.V05, _VerifierVersion.V04, _VerifierVersion.V03,
                                   _VerifierVersion.V02))
            or script == _historical_lock(public_key, compact=True)
            or script == _historical_lock(public_key, compact=False))

"""OpenSSL-backed reference for pure FIPS 204 ML-DSA-44."""

from pathlib import Path
import subprocess
import tempfile

from fips204 import PUBLIC_KEY_BYTES, SIGNATURE_BYTES, verify

DIGEST_BYTES = 32

# SubjectPublicKeyInfo for id-ml-dsa-44. The algorithm takes no parameters.
_PUBLIC_KEY_DER_PREFIX = bytes.fromhex("30820532300b06096086480165030403110382052100")


def _check_message(message, context):
    if not isinstance(message, bytes) or not isinstance(context, bytes):
        raise TypeError("message and context must be bytes")
    if len(context) > 255:
        raise ValueError("ML-DSA context exceeds 255 bytes")


def _message_input(message, context):
    # OpenSSL 3.5 pkeyutl's one-shot path cannot read a zero-byte file.
    # Supply the exact Pure ML-DSA encoding and skip the CLI's framing in this case.
    if not message:
        return bytes((0, len(context))) + context, ["-pkeyopt", "message-encoding:0"]
    parameters = ["-pkeyopt", "message-encoding:1"]
    if context:
        parameters.extend(("-pkeyopt", f"hexcontext-string:{context.hex()}"))
    return message, parameters


def _openssl(executable, arguments):
    return subprocess.run([executable, *arguments], capture_output=True, timeout=30)


def verify_openssl(public_key, message, signature, *, context=b"", openssl="openssl"):
    """Verify raw public key and signature bytes using Pure ML-DSA-44."""
    _check_message(message, context)
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        return False
    if not isinstance(signature, bytes) or len(signature) != SIGNATURE_BYTES:
        return False
    input_bytes, parameters = _message_input(message, context)

    with tempfile.TemporaryDirectory(prefix="ml-dsa-verify-") as directory:
        public_file = Path(directory, "public.der")
        message_file = Path(directory, "message")
        signature_file = Path(directory, "signature")
        public_file.write_bytes(_PUBLIC_KEY_DER_PREFIX + public_key)
        message_file.write_bytes(input_bytes)
        signature_file.write_bytes(signature)
        result = _openssl(openssl, [
            "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
            "-inkey", str(public_file), "-in", str(message_file),
            "-sigfile", str(signature_file), *parameters,
        ])
    if result.returncode == 0:
        return True
    if result.stdout.strip() == b"Signature Verification Failure":
        return False
    result.check_returncode()


def authorize_digest(public_key, digest, signer, *, context=b""):
    """Call signer(digest, context) and verify its raw signature.

    The caller must approve the transaction and derive the supplied digest.
    The callback holds the signing key and owns authorization and key policy.
    """
    _check_message(digest, context)
    if len(digest) != DIGEST_BYTES:
        raise ValueError("transaction digest must be 32 bytes")
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError("ML-DSA-44 public key must be 1,312 bytes")
    signature = signer(digest, context)
    if not verify(public_key, digest, signature, context=context):
        raise ValueError("invalid ML-DSA-44 signature from external signer")
    return signature


def test_only_vector(seed, message, *, context=b"", openssl="openssl"):
    """Generate reproducible vectors with a public seed and deterministic rnd."""
    _check_message(message, context)
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("test seed must be 32 bytes")
    input_bytes, parameters = _message_input(message, context)
    with tempfile.TemporaryDirectory(prefix="ml-dsa-vector-") as directory:
        private_file = Path(directory, "test-only-private.der")
        message_file = Path(directory, "message")
        key_result = _openssl(openssl, [
            "genpkey", "-algorithm", "ML-DSA-44", "-outform", "DER",
            "-pkeyopt", f"hexseed:{seed.hex()}",
        ])
        key_result.check_returncode()
        private_file.write_bytes(key_result.stdout)
        message_file.write_bytes(input_bytes)
        public_result = _openssl(openssl, [
            "pkey", "-in", str(private_file), "-inform", "DER", "-pubout", "-outform", "DER",
        ])
        public_result.check_returncode()
        public_der = public_result.stdout
        public_key = public_der.removeprefix(_PUBLIC_KEY_DER_PREFIX)
        if public_key == public_der or len(public_key) != PUBLIC_KEY_BYTES:
            raise ValueError("unexpected ML-DSA-44 SubjectPublicKeyInfo")
        signature_result = _openssl(openssl, [
            "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", str(private_file),
            "-in", str(message_file), "-pkeyopt", "deterministic:1", *parameters,
        ])
        signature_result.check_returncode()
        signature = signature_result.stdout
    if len(signature) != SIGNATURE_BYTES:
        raise ValueError("unexpected ML-DSA-44 signature length")
    return public_key, signature

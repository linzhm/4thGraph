"""Public FIPS 205 verifier tests and OpenSSL-only test key creation."""

import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from slh import FORS_BYTES, FORS_TREE_BYTES, KEY_BYTES, N, SIGNATURE_BYTES, WOTS_BYTES, XMSS_BYTES, verify


ALGORITHM = 'SLH-DSA-SHA2-128s'
SPKI_PREFIX = bytes.fromhex('3030300b0609608648016503040314032100')
VECTOR = Path(__file__).resolve().parents[1] / 'template' / 'vector.json'


def _openssl(*args):
    binary = os.environ.get('SLH_DSA_OPENSSL', 'openssl')
    return subprocess.run([binary, *args], check=True, capture_output=True, timeout=30).stdout


def openssl_test_key(directory, *, seed_test_only=bytes(range(3 * N))):
    """Return the public key and private key path for a public test seed."""
    if not isinstance(seed_test_only, bytes) or len(seed_test_only) != 3 * N:
        raise ValueError('test seed must be 48 bytes')
    private_path = directory / 'test-key.pem'
    _openssl('genpkey', '-algorithm', ALGORITHM, '-pkeyopt', f'hexseed:{seed_test_only.hex()}',
             '-out', str(private_path))
    encoded = _openssl('pkey', '-in', str(private_path), '-pubout', '-outform', 'DER')
    if not encoded.startswith(SPKI_PREFIX) or len(encoded) != len(SPKI_PREFIX) + KEY_BYTES:
        raise ValueError('unexpected SLH-DSA-SHA2-128s SubjectPublicKeyInfo')
    return encoded[len(SPKI_PREFIX):], private_path


def openssl_test_sign(directory, private_path, message, *, context=None):
    """Sign test inputs only with the OpenSSL CLI."""
    message_path = directory / 'message.bin'
    message_path.write_bytes(message)
    args = ['pkeyutl', '-sign', '-rawin', '-inkey', str(private_path),
            '-in', str(message_path), '-pkeyopt', 'deterministic:1']
    if context is not None:
        args.extend(('-pkeyopt', f'hexcontext-string:{context.hex()}'))
    return _openssl(*args)


def load_vector():
    vector = json.loads(VECTOR.read_text())
    return tuple(bytes.fromhex(vector[field]) for field in ('public_key', 'message', 'signature'))


class SLHDSATests(unittest.TestCase):
    def test_openssl_vector(self):
        public_key, message, signature = load_vector()
        self.assertEqual(len(public_key), 32)
        self.assertEqual(len(signature), 7856)
        self.assertTrue(verify(public_key, message, signature))

    def test_rejects_wrong_message_and_key(self):
        public_key, message, signature = load_vector()
        self.assertFalse(verify(public_key, message + b'\0', signature))
        self.assertFalse(verify(public_key, b'\0\0' + message, signature))
        for index in (0, N):
            changed = bytearray(public_key)
            changed[index] ^= 1
            self.assertFalse(verify(bytes(changed), message, signature))

    def test_rejects_mutations_in_every_signature_layer(self):
        public_key, message, signature = load_vector()
        offsets = [0]
        for offset in range(N, N + FORS_BYTES, FORS_TREE_BYTES):
            offsets.extend((offset, offset + N))
        for offset in range(N + FORS_BYTES, SIGNATURE_BYTES, XMSS_BYTES):
            offsets.extend((offset, offset + WOTS_BYTES))
        for offset in offsets:
            with self.subTest(offset=offset):
                changed = bytearray(signature)
                changed[offset] ^= 1
                self.assertFalse(verify(public_key, message, bytes(changed)))

    def test_rejects_wrong_lengths_and_types(self):
        public_key, message, signature = load_vector()
        self.assertFalse(verify(public_key[:-1], message, signature))
        self.assertFalse(verify(public_key + b'\0', message, signature))
        self.assertFalse(verify(public_key, message, signature[:-1]))
        self.assertFalse(verify(public_key, message, signature + b'\0'))
        self.assertFalse(verify(public_key, message.hex(), signature))

    def test_reproduce_vector_and_sign_several_messages_with_same_key(self):
        try:
            available = ALGORITHM.encode() in _openssl('list', '-signature-algorithms')
        except (FileNotFoundError, subprocess.CalledProcessError):
            available = False
        if not available:
            self.skipTest('OpenSSL with SLH-DSA support is not installed')

        public_key, message, signature = load_vector()
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            generated_key, private = openssl_test_key(directory)
            self.assertEqual(generated_key, public_key)
            self.assertEqual(openssl_test_sign(directory, private, message), signature)

            second_message = b'second message signed by the same stateless test key'
            second_signature = openssl_test_sign(directory, private, second_message)
            self.assertTrue(verify(public_key, second_message, second_signature))
            self.assertFalse(verify(public_key, message, second_signature))

            wrong_context = openssl_test_sign(directory, private, message, context=b'other-context')
            self.assertFalse(verify(public_key, message, wrong_context))


if __name__ == '__main__':
    unittest.main()

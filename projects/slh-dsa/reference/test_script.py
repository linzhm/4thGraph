"""Exercise the emitted SLH-DSA Script with the independent OpenSSL vector."""
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from script import locking_script, verifier
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push
from slh import FORS_BYTES, N, WOTS_BYTES, XMSS_BYTES
from test_slh import ALGORITHM, _openssl, load_vector, openssl_test_key, openssl_test_sign


class ScriptTests(unittest.TestCase):
    def test_detached_openssl_vector(self):
        key, message, signature = load_vector()
        lock = locking_script(key, transaction=False)
        self.assertEqual(evaluate(lock, [message, signature]), ([b'\x01'], []))

    def test_openssl_second_key_and_variable_length_message(self):
        try:
            available = ALGORITHM.encode() in _openssl('list', '-signature-algorithms')
        except (FileNotFoundError, subprocess.CalledProcessError):
            available = False
        if not available:
            self.skipTest('OpenSSL with SLH-DSA support is not installed')

        prior_key, _, _ = load_vector()
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            key, private = openssl_test_key(directory, seed_test_only=bytes(range(48, 96)))
            message = b'SLH-DSA verification with an independently seeded key and a longer message'
            signature = openssl_test_sign(directory, private, message)

        self.assertNotEqual(key, prior_key)
        self.assertEqual(evaluate(locking_script(key, transaction=False), [message, signature]),
                         ([b'\x01'], []))
        with self.assertRaises(ScriptError):
            evaluate(locking_script(prior_key, transaction=False), [message, signature])

    def test_preserves_the_callers_stacks(self):
        key, message, signature = load_vector()
        alternate = b'outer alternate stack value'
        main = b'outer main stack value'
        program = push(alternate) + asm('OP_TOALTSTACK') + verifier(key)
        self.assertEqual(evaluate(program, [main, signature, message]), ([main], [alternate]))

    def test_rejects_key_message_and_signature_changes(self):
        key, message, signature = load_vector()
        lock = locking_script(key, transaction=False)
        changed_key = bytes([key[0] ^ 1]) + key[1:]
        with self.assertRaises(ScriptError):
            evaluate(locking_script(changed_key, transaction=False), [message, signature])
        with self.assertRaises(ScriptError):
            evaluate(lock, [message + b'\0', signature])
        hypertree = N + FORS_BYTES
        for offset in (0, N, N + N, hypertree, hypertree + WOTS_BYTES, hypertree + 6 * XMSS_BYTES):
            with self.subTest(offset=offset):
                changed = signature[:offset] + bytes([signature[offset] ^ 1]) + signature[offset + 1:]
                with self.assertRaises(ScriptError):
                    evaluate(lock, [message, changed])

    def test_rejects_malformed_detached_stacks(self):
        key, message, signature = load_vector()
        lock = locking_script(key, transaction=False)
        for stack in ([message], [message, signature[:-1]], [message, signature + b'\0'],
                      [b'extra', message, signature]):
            with self.subTest(lengths=list(map(len, stack))):
                with self.assertRaises(ScriptError):
                    evaluate(lock, stack)
        with self.assertRaises(ValueError):
            locking_script(key[:-1])


if __name__ == '__main__':
    unittest.main()

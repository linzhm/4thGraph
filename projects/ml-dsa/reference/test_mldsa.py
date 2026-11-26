"""Cross-check the Script arithmetic, FIPS verifier, and external signer API."""

from hashlib import sha256
import json
from pathlib import Path
import random
import unittest

from fips204 import PUBLIC_KEY_BYTES, _GAMMA2, _pack, _use_hint, verification_equation, verify
from hint_script import apply_hints_before_rounding_script, apply_hints_script, apply_sparse_hints_script
from mldsa import authorize_digest, test_only_vector as deterministic_test_vector, verify_openssl
from ntt_script import checked_equation_script, ring_product_script, transform_script, verification_equation_script
from polynomial import DEGREE, MODULUS, ROOT_OF_UNITY, inverse_ntt, ntt
from signature_script import RESPONSE_NORM_LIMIT
from fourthgraph.bsv.evaluate import ScriptError, evaluate

_FIXTURES = Path(__file__).resolve().parents[1] / "versions/v0.1.0"


def pack(coefficients):
    return b"".join(coefficient.to_bytes(3, "little") for coefficient in coefficients)


def synthetic_polynomials():
    random_source = random.Random(204)
    return tuple([random_source.randrange(MODULUS) for _ in range(DEGREE)] for _ in range(2))


def equation_fixture():
    public_key = bytes(((index * 3 + 2) % 256) for index in range(PUBLIC_KEY_BYTES))
    random_source = random.Random(205)
    challenge = [random_source.randrange(-1, 2) for _ in range(DEGREE)]
    responses = [[random_source.randrange(-500, 501) for _ in range(DEGREE)] for _ in range(4)]
    witness = b"".join(pack([value % MODULUS for value in polynomial]) for polynomial in (challenge, *responses))
    expected = b"".join(pack(row) for row in verification_equation(public_key, challenge, responses))
    return public_key, witness, expected


def hint_fixture():
    random_source = random.Random(206)
    boundaries = sorted({
        boundary + delta
        for center in range(0, MODULUS, 2 * _GAMMA2)
        for boundary in (center, center + _GAMMA2)
        for delta in (-1, 0, 1)
        if 0 <= boundary + delta < MODULUS
    })
    values = [value for boundary in boundaries for value in (boundary, boundary)]
    values.extend(random_source.randrange(MODULUS) for _ in range(4 * DEGREE - len(values)))
    boundary_count = 2 * len(boundaries)
    hint_indices = frozenset((*range(1, boundary_count, 2), *range(boundary_count, 4 * DEGREE, 3)))
    hints = bytes(sum(1 << bit for bit in range(8) if offset + bit in hint_indices)
                  for offset in range(0, 4 * DEGREE, 8))
    high = [_use_hint(value, index in hint_indices) for index, value in enumerate(values)]
    encoded = sum(value << (6 * index) for index, value in enumerate(high)).to_bytes(768, "little")
    return pack(values), hints, encoded


def direct_evaluation(coefficients):
    """Evaluate each NTT point with Horner's rule, independent of butterflies."""
    values = []
    for position in range(DEGREE):
        root_index = int(f"{position:08b}"[::-1], 2)
        point = pow(ROOT_OF_UNITY, 2 * root_index + 1, MODULUS)
        value = 0
        for coefficient in reversed(coefficients):
            value = (value * point + coefficient) % MODULUS
        values.append(value)
    return values


def negacyclic_product(left, right):
    """Compute the expected ring product directly using X^256 = -1."""
    output = [0] * DEGREE
    for left_index, first in enumerate(left):
        for right_index, second in enumerate(right):
            power = left_index + right_index
            if power < DEGREE:
                output[power] += first * second
            else:
                output[power - DEGREE] -= first * second
    return [value % MODULUS for value in output]


class ArithmeticTests(unittest.TestCase):
    def test_apply_hints_and_pack_high_bits(self):
        rows, hints, expected = hint_fixture()
        kernel = apply_hints_script()
        self.assertEqual(evaluate(kernel, [rows, hints]), ([expected], []))
        with self.assertRaises(ScriptError):
            evaluate(kernel, [rows, hints[:-1]])

    def test_sparse_hints_patch_shared_groups_and_wrap_high_bits(self):
        alpha = 2 * _GAMMA2
        boundary = (0, 43 * alpha + 1, MODULUS - 1, 43 * alpha, _GAMMA2, _GAMMA2 + 1)
        residues = [boundary[index % len(boundary)] for index in range(4 * DEGREE)]
        rows = pack(residues)
        kept = b"caller stack item"
        full_weight = (*range(70), 254, 255, 256, 257, 510, 511, 512, 513, 1022, 1023)
        for hints in ((), full_weight):
            with self.subTest(weight=len(hints)):
                sparse = b"".join(index.to_bytes(2, "little") for index in hints)
                expected = _pack([_use_hint(value, index in hints)
                                  for index, value in enumerate(residues)], 6)
                for compiler in (apply_sparse_hints_script, apply_hints_before_rounding_script):
                    self.assertEqual(evaluate(compiler(), [kept, rows, sparse]), ([kept, expected], []))

    def test_fixed_key_verification_equation(self):
        key, witness, expected = equation_fixture()
        for compact in (False, True):
            with self.subTest(compact=compact):
                kernel = verification_equation_script(key, compact=compact)
                self.assertEqual(evaluate(kernel, [witness]), ([expected], []))
                with self.assertRaises(ScriptError):
                    evaluate(kernel, [witness[:-1]])

    def test_checked_equation_with_signed_response_boundaries(self):
        public_key, _, _ = equation_fixture()
        limit = RESPONSE_NORM_LIMIT - 1
        challenge = [-1, 1] + [0] * (DEGREE - 2)
        response = ([limit] * DEGREE, [-limit] * DEGREE, [0] * DEGREE, [1, -1] * (DEGREE // 2))
        responses = b"".join(pack([abs(value) | (0x800000 if value < 0 else 0) for value in row])
                             for row in response)
        signed_challenge = bytes(abs(value) | (0x80 if value < 0 else 0) for value in challenge)
        expected = b"".join(pack(row) for row in verification_equation(public_key, challenge, response))
        kept = b"caller stack item"
        kernel = checked_equation_script(public_key, signed_challenge=True)
        self.assertEqual(evaluate(kernel, [kept, signed_challenge + responses]), ([kept, expected], []))

    def test_forward_and_inverse_ntt(self):
        batch = ([0] * DEGREE, [0] * (DEGREE - 1) + [MODULUS - 1], *synthetic_polynomials())
        for index, polynomial in enumerate(batch):
            with self.subTest(index=index):
                expected = direct_evaluation(polynomial)
                self.assertEqual(ntt(polynomial), expected)
                self.assertEqual(inverse_ntt(expected), polynomial)
                kept = b"caller stack item"
                self.assertEqual(evaluate(transform_script(), [kept, pack(polynomial)]), ([kept, pack(expected)], []))
                self.assertEqual(evaluate(transform_script(inverse=True), [pack(expected)]), ([pack(polynomial)], []))

    def test_ring_product(self):
        random_pair = synthetic_polynomials()
        wrap_pair = ([0] * 255 + [1], [0, 1] + [0] * 254)
        for left, right in (random_pair, wrap_pair):
            expected = pack(negacyclic_product(left, right))
            self.assertEqual(evaluate(ring_product_script(), [pack(left), pack(right)]), ([expected], []))

    def test_noncanonical_packed_coefficients(self):
        length = DEGREE * 3
        for malformed in (bytes(length - 1), bytes(length + 1),
                          MODULUS.to_bytes(3, "little") + bytes(length - 3),
                          bytes.fromhex("000080") + bytes(length - 3)):
            for compact in (False, True):
                with self.subTest(prefix=malformed[:3].hex(), length=len(malformed), compact=compact):
                    with self.assertRaises(ScriptError):
                        evaluate(transform_script(compact=compact), [malformed])


class FipsTests(unittest.TestCase):
    def test_deterministic_vector_and_signer(self):
        vector = json.loads((_FIXTURES / "deterministic.json").read_text())
        seed = bytes.fromhex(vector["seed_test_only"])
        message = bytes.fromhex(vector["message"])
        context = bytes.fromhex(vector["context"])
        key, signature = deterministic_test_vector(seed, message, context=context)
        self.assertEqual(sha256(key).hexdigest(), vector["public_key_sha256"])
        self.assertEqual(sha256(signature).hexdigest(), vector["signature_sha256"])
        self.assertTrue(verify(key, message, signature, context=context))
        self.assertTrue(verify_openssl(key, message, signature, context=context))

        calls = []

        def external_signer(digest, signing_context):
            calls.append((digest, signing_context))
            return signature

        self.assertEqual(authorize_digest(key, message, external_signer, context=context), signature)
        self.assertEqual(calls, [(message, context)])
        with self.assertRaises(ValueError):
            authorize_digest(key, message[:-1], external_signer, context=context)
        self.assertEqual(len(calls), 1)
        with self.assertRaises(ValueError):
            authorize_digest(key, message, lambda *_: b"", context=context)

    def test_mutations_and_context_boundary(self):
        seed = bytes(range(32))
        context = bytes(range(255))
        message = b""
        key, signature = deterministic_test_vector(seed, message, context=context)
        self.assertTrue(verify(key, message, signature, context=context))
        self.assertTrue(verify_openssl(key, message, signature, context=context))
        malformed_hint = signature[:-1] + b"\xff"
        invalid_signatures = (signature[:-1], signature + b"\0", malformed_hint,
                              bytes((signature[0] ^ 1,)) + signature[1:])
        for invalid in invalid_signatures:
            self.assertFalse(verify(key, message, invalid, context=context))
            self.assertFalse(verify_openssl(key, message, invalid, context=context))
        self.assertFalse(verify(key, message, signature, context=context + b"\0"))
        self.assertFalse(verify(key, message, signature))
        self.assertFalse(verify(key, message, signature, context=context[:-1]))
        self.assertFalse(verify(key, b"other", signature, context=context))
        self.assertFalse(verify(key[:-1], message, signature, context=context))


if __name__ == "__main__":
    unittest.main()

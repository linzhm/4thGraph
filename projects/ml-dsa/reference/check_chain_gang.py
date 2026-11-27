"""Validate arithmetic in complete synthetic transactions under explicit eras."""

from dataclasses import replace
import os
import unittest

from fips204 import GAMMA1, RESPONSE_BITS, RESPONSE_NORM_LIMIT, _pack, verification_equation
from hint_script import apply_hints_script
from mldsa import test_only_vector as make_test_vector
from ntt_script import (
    packed_response_equation_script, ring_product_script, transform_script, verification_equation_script,
)
from script import verify_message_script
from fourthgraph.benchmark.validation import Node
from fourthgraph.bsv.chain_gang import validate_at_heights
from polynomial import DEGREE, MODULUS
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from test_mldsa import (
    direct_evaluation, equation_fixture, hint_fixture, negacyclic_product, pack, synthetic_polynomials,
)


def _case(kernel, values, expected):
    # For rejection fixtures the kernel must fail before the final OP_1.
    finish = asm("OP_DROP OP_1") if expected is None else push(expected) + asm("OP_EQUAL")
    lock = kernel + finish
    parent = Transaction((Input(b"\x3e" * 32, 0),), (Output(10_000, lock),))
    witness = b"".join(push(value) for value in values)
    spend = Transaction((Input(parent.txid_wire(), 0, witness),), (Output(9_900, asm("OP_1")),))
    return parent, spend


def _validate(parent, spend, version, creation_height, spending_height):
    return validate_at_heights(
        replace(spend, version=version), [parent], spend_height=spending_height,
        activation_height=3, utxo_heights=[creation_height],
    )


class ChronicleArithmeticTests(unittest.TestCase):
    def test_packed_response_equation_matches_signed_boundaries(self):
        key, _, _ = equation_fixture()
        limit = RESPONSE_NORM_LIMIT - 1
        challenge = [-1, 0, 1, 0] * (DEGREE // 4)
        response = ([limit] * DEGREE, [-limit] * DEGREE, [0] * DEGREE, [1, -1] * (DEGREE // 2))
        signed_challenge = bytes(abs(value) | (0x80 if value < 0 else 0) for value in challenge)
        encoded_response = _pack([GAMMA1 - value for row in response for value in row], RESPONSE_BITS)
        expected = b"".join(pack(row) for row in verification_equation(key, challenge, response))
        kernel = packed_response_equation_script(key, compact_packing=True)
        parent, spend = _case(kernel, (signed_challenge + encoded_response,), expected)
        _validate(parent, spend, 1, 1, 2)
        _validate(parent, spend, 2, 3, 4)

    def test_complete_input_eras(self):
        left, right = synthetic_polynomials()
        transformed = pack(direct_evaluation(left))
        key, equation_input, equation_expected = equation_fixture()
        rows, hints, high_bits = hint_fixture()
        cases = [
            (transform_script(), (pack(left),), transformed),
            (transform_script(inverse=True), (transformed,), pack(left)),
            (ring_product_script(), (pack(left), pack(right)), pack(negacyclic_product(left, right))),
            (verification_equation_script(key), (equation_input,), equation_expected),
            (apply_hints_script(), (rows, hints), high_bits),
        ]
        # Genesis-era creation/spend, Genesis-era UTXO crossing activation, and
        # Chronicle-era creation/spend. Exercise strict and relaxed tx versions.
        for version in (1, 2):
            for creation_height, spending_height in ((1, 2), (1, 3), (3, 4)):
                for index, (kernel, values, expected) in enumerate(cases):
                    with self.subTest(version=version, creation_height=creation_height,
                                      spending_height=spending_height, kernel=index):
                        parent, spend = _case(kernel, values, expected)
                        _validate(parent, spend, version, creation_height, spending_height)

                        incorrect = bytes((expected[0] ^ 1,)) + expected[1:]
                        parent, spend = _case(kernel, values, incorrect)
                        with self.assertRaisesRegex(ValueError, "Top of stack is false"):
                            _validate(parent, spend, version, creation_height, spending_height)

    def test_reduced_ntt_kernels_match_independent_canonical_results(self):
        node = None
        if cookie := os.environ.get("REGTEST_COOKIE"):
            node = Node(os.environ.get("REGTEST_URL", "http://127.0.0.1:18443"), cookie)
        left, _ = synthetic_polynomials()
        extremes = tuple((MODULUS - 1) * (index % 2) for index in range(DEGREE))
        key, equation_input, expected = equation_fixture()
        for options in ({"signed_residues": True}, {"compact": True}):
            forward = transform_script(**options)
            inverse = transform_script(inverse=True, **options)
            self.assertLess(len(forward), len(transform_script()))
            self.assertLess(len(inverse), len(transform_script(inverse=True)))
            for label, coefficients in (("fixture", left), ("alternating extremes", extremes),
                                        ("zeros", (0,) * DEGREE)):
                transformed = pack(direct_evaluation(coefficients))
                for direction, kernel, source, target in (
                        ("forward", forward, pack(coefficients), transformed),
                        ("inverse", inverse, transformed, pack(coefficients))):
                    with self.subTest(polynomial=label, direction=direction, **options):
                        parent, spend = _case(kernel, (source,), target)
                        _validate(parent, spend, 2, 3, 4)
                        if node:
                            self.assertEqual(node.verdicts(spend, (parent,)), [True])
            equation = verification_equation_script(key, **options)
            self.assertLess(len(equation), len(verification_equation_script(key)))
            for valid, target in ((True, expected), (False, bytes([expected[0] ^ 1]) + expected[1:])):
                with self.subTest(valid=valid, **options):
                    parent, spend = _case(equation, (equation_input,), target)
                    if valid:
                        _validate(parent, spend, 2, 3, 4)
                    else:
                        with self.assertRaisesRegex(ValueError, "Top of stack is false"):
                            _validate(parent, spend, 2, 3, 4)
                    if node:
                        self.assertEqual(node.verdicts(spend, (parent,)), [valid])

    def test_generic_verifier_authenticates_context_for_empty_message(self):
        message = b""
        context = bytes(range(255))
        key, signature = make_test_vector(bytes(range(32)), message, context=context)
        verifier = verify_message_script(key, len(message), context=context)
        parent, spend = _case(verifier, (message, signature), b"\x01")
        _validate(parent, spend, 2, 3, 4)

        changed_context = b"\xff" + context[1:]
        verifier = verify_message_script(key, len(message), context=changed_context)
        parent, spend = _case(verifier, (message, signature), b"\x01")
        with self.assertRaisesRegex(ValueError, "Top of stack is false"):
            _validate(parent, spend, 2, 3, 4)


if __name__ == "__main__":
    unittest.main()

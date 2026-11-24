"""Validate arithmetic in complete synthetic transactions under explicit eras."""

from dataclasses import replace
import unittest

from hint_script import apply_hints_script
from mldsa import test_only_vector as make_test_vector
from ntt_script import ring_product_script, transform_script, verification_equation_script
from script import verify_message_script
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction
from test_mldsa import (
    direct_evaluation, equation_fixture, hint_fixture, negacyclic_product, pack, synthetic_polynomials,
)


def _case(kernel, values, expected):
    lock = kernel + push(expected) + asm("OP_EQUAL")
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

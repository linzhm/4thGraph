"""Complete ML-DSA-44 payments across Chronicle activation contexts."""

from dataclasses import replace
import os
import unittest

from mldsa import test_only_vector as make_test_vector
from payment import authorization, sign_spend
from script import locking_script
from shared.chain_gang import validate_at_heights
from shared.transaction import CHRONICLE, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_TYPES, Input, Output, Transaction


TEST_SEED = bytes(range(32))


class PaymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = os.environ.get('ML_DSA_OPENSSL', 'openssl')
        cls.public_key, _ = make_test_vector(TEST_SEED, bytes(32), openssl=cls.openssl)
        funding = Transaction((Input(b'\x61' * 32, 0),), (Output(10_000, locking_script(cls.public_key)),))
        other = Transaction((Input(b'\x42' * 32, 0),), (Output(1_000, b'\x51'),))
        cls.parents = other, funding
        cls.funding_raw = funding.serialize()

    def signer(self, digest):
        public_key, signature = make_test_vector(TEST_SEED, digest, openssl=self.openssl)
        self.assertEqual(public_key, self.public_key)
        return signature

    def payment(self, flag, version, paired):
        inputs = tuple(Input(parent.txid_wire(), 0) for parent in self.parents)
        outputs = (Output(500, b'\x51'), Output(10_400, b'\x51')) if paired else (Output(10_900, b'\x51'),)
        tx = Transaction(inputs, outputs, version=version)
        auth = authorization(tx, 1, 10_000, flag)
        self.assertEqual(auth.companion, bool(flag & CHRONICLE) and flag & 31 == SIGHASH_SINGLE and not paired)
        return sign_spend(tx, 1, self.funding_raw, self.public_key, self.signer, sighash=flag)

    def check_spend(self, spend, expected, height, creation_heights):
        arguments = {'spend_height': height, 'activation_height': 3, 'utxo_heights': creation_heights}
        if expected:
            validate_at_heights(spend, self.parents, **arguments)
        else:
            with self.assertRaises((RuntimeError, ValueError)):
                validate_at_heights(spend, self.parents, **arguments)

    def test_sighash_activation_and_output_eras(self):
        for version in (1, 2):
            for flag in sorted(SIGHASH_TYPES):
                for paired in (True, False) if flag & 31 == SIGHASH_SINGLE else (True,):
                    with self.subTest(version=version, sighash=hex(flag), paired=paired):
                        spend = self.payment(flag, version, paired)
                        for height, creation in ((2, (1, 1)), (4, (1, 1)), (4, (1, 3)), (4, (3, 3))):
                            with self.subTest(height=height, creation=creation):
                                self.check_spend(spend, height >= 3 or not flag & CHRONICLE, height, creation)

                        last = replace(spend.outputs[-1], value=spend.outputs[-1].value - 1)
                        changed = replace(spend, outputs=(*spend.outputs[:-1], last))
                        self.check_spend(changed, not paired or flag & 31 == SIGHASH_NONE, 4, (3, 3))
                        self.check_spend(replace(spend, locktime=1), False, 4, (3, 3))

    def test_invalid_signer_response(self):
        signed = self.payment(0x41, 2, True)
        unsigned = signed.with_script(1, b'')
        with self.assertRaisesRegex(ValueError, 'invalid ML-DSA-44 signature'):
            sign_spend(unsigned, 1, self.funding_raw, self.public_key, lambda digest: b'')


if __name__ == '__main__':
    unittest.main()

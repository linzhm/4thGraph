"""Complete SLH-DSA payments under explicit Chronicle activation heights."""

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from payment import authorization, sign_spend
from script import locking_script
from shared.chain_gang import validate_at_heights
from shared.transaction import CHRONICLE, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_TYPES, Input, Output, Transaction
from test_slh import openssl_test_key, openssl_test_sign


class PaymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = TemporaryDirectory(prefix='slh-payment-')
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.directory = Path(cls.scratch.name)
        cls.public_key, cls.key_path = openssl_test_key(cls.directory)
        cls.funding = Transaction(
            (Input(b'\x66' * 32, 0),),
            (Output(10_000, locking_script(cls.public_key)),),
        )
        cls.other = Transaction((Input(b'\x44' * 32, 0),), (Output(1_000, b'\x51'),))
        cls.parents = cls.other, cls.funding

    def signer(self, digest):
        return openssl_test_sign(self.directory, self.key_path, digest)

    def payment(self, flag, version, paired):
        inputs = tuple(Input(parent.txid_wire(), 0) for parent in self.parents)
        outputs = (Output(500, b'\x51'), Output(10_400, b'\x51')) if paired else (Output(10_900, b'\x51'),)
        tx = Transaction(inputs, outputs, version=version)
        auth = authorization(tx, 1, 10_000, flag)
        self.assertEqual(auth.companion, bool(flag & CHRONICLE) and flag & 31 == SIGHASH_SINGLE and not paired)
        return sign_spend(tx, 1, self.funding.serialize(), self.public_key, self.signer, sighash=flag)

    def check_spend(self, spend, expected, spend_height, creation_heights):
        arguments = {
            'spend_height': spend_height,
            'activation_height': 3,
            'utxo_heights': creation_heights,
        }
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
                        altered = replace(spend, outputs=(*spend.outputs[:-1], last))
                        self.check_spend(altered, not paired or flag & 31 == SIGHASH_NONE, 4, (3, 3))
                        self.check_spend(replace(spend, locktime=1), False, 4, (3, 3))

    def test_invalid_signer_response(self):
        spend = self.payment(0x41, 2, True)
        unsigned = spend.with_script(1, b'')
        with self.assertRaisesRegex(ValueError, 'invalid SLH-DSA signature'):
            sign_spend(unsigned, 1, self.funding.serialize(), self.public_key, lambda digest: b'')


if __name__ == '__main__':
    unittest.main()

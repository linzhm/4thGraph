"""Exercise WOTS+ using the updated chain-gang explicit-height API."""

from itertools import chain
import unittest

from fixtures import malformed_cases, mode_cases, mode_fixture
from shared.chain_gang import validate_at_heights
from shared.transaction import CHRONICLE, SIGHASH_SINGLE, SIGHASH_TYPES


class ChronicleTests(unittest.TestCase):
    def check_spend(self, spend, parents, expected, spend_height, creation_heights):
        parameters = {
            'spend_height': spend_height,
            'activation_height': 3,
            'utxo_heights': creation_heights,
        }
        if expected:
            validate_at_heights(spend, parents, **parameters)
        else:
            with self.assertRaises((RuntimeError, ValueError)):
                validate_at_heights(spend, parents, **parameters)

    def test_complete_input_matrix(self):
        for case, spend, parents, _, expected in chain(mode_cases(), malformed_cases()):
            with self.subTest(case=case):
                self.check_spend(spend, parents, expected, 4, (3, 3))

    def test_activation_and_output_eras(self):
        for version in (1, 2):
            for flag in sorted(SIGHASH_TYPES):
                for paired in (True, False) if flag & 31 == SIGHASH_SINGLE else (True,):
                    _, parents, spend = mode_fixture(flag, paired=paired, version=version)
                    for height, creation in ((2, (1, 1)), (4, (1, 1)), (4, (1, 3)), (4, (3, 3))):
                        with self.subTest(version=version, sighash=hex(flag), paired=paired, height=height, creation=creation):
                            expected = height >= 3 or not flag & CHRONICLE
                            self.check_spend(spend, parents, expected, height, creation)


if __name__ == '__main__':
    unittest.main()

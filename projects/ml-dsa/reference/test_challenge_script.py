"""Check the bounded ML-DSA challenge sampler against the FIPS reference."""

import unittest

from challenge_script import DEFAULT_STREAM_BYTES, sample_from_stream_script, sample_in_ball_script
from fips204 import sample_challenge
from polynomial import MODULUS
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction


def pack(polynomial):
    return b''.join((value % MODULUS).to_bytes(3, 'little') for value in polynomial)


class ChallengeScriptTests(unittest.TestCase):
    def check(self, script, value, expected, *, version=2, creation=3, height=4):
        if expected is None:
            lock = script + asm('OP_DROP OP_1')
        else:
            lock = script + push(expected) + asm('OP_EQUAL')
        parent = Transaction((Input(b'\xfa' * 32, 0),), (Output(1_000, lock),))
        spend = Transaction((Input(parent.txid_wire(), 0, push(value)),), (Output(900, b'\x51'),), version=version)
        args = dict(spend_height=height, activation_height=3, utxo_heights=(creation,))
        if expected is None:
            with self.assertRaises((RuntimeError, ValueError)):
                validate_at_heights(spend, (parent,), **args)
        else:
            validate_at_heights(spend, (parent,), **args)

    def test_challenge_matches_fips_204_across_chronicle(self):
        script = sample_in_ball_script()
        for challenge in (bytes(32), bytes(range(32)), b'\xff' * 32):
            expected = pack(sample_challenge(challenge))
            for version in (1, 2):
                for creation, height in ((1, 2), (1, 4), (3, 4)):
                    with self.subTest(version=version, creation=creation, height=height, challenge=challenge.hex()):
                        self.check(script, challenge, expected, version=version, creation=creation, height=height)

    def test_rejections_do_not_advance_the_challenge(self):
        script = sample_from_stream_script()
        stream = b'\xff' * 8 + b'\xff' * (DEFAULT_STREAM_BYTES - 8 - 39) + bytes(range(39))
        expected = pack([-1] * 39 + [0] * (256 - 39))
        self.check(script, stream, expected)
        self.check(script, b'\xff' * DEFAULT_STREAM_BYTES, None)
        self.check(script, stream[:-1], None)


if __name__ == '__main__':
    unittest.main()

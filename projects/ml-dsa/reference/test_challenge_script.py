"""Check the bounded ML-DSA challenge sampler against the FIPS reference."""

import unittest

from challenge_script import sample_from_stream_script, sample_in_ball_script
from fips204 import CHALLENGE_SIGN_BYTES, CHALLENGE_WEIGHT, SAMPLE_IN_BALL_BYTES, sample_challenge
from polynomial import DEGREE, MODULUS
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from tx_engine import Context, Script


def pack(polynomial, *, signed=False):
    if signed:
        return bytes(abs(value) | (0x80 if value < 0 else 0) for value in polynomial)
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
        script = sample_in_ball_script(signed=True, search=True, vector_bytes=True,
                                       direct_absorb=True, find_by_borrow=True)
        for challenge in (bytes(32), bytes(range(32)), b'\xff' * 32):
            expected = pack(sample_challenge(challenge), signed=True)
            for version in (1, 2):
                for creation, height in ((1, 2), (1, 4), (3, 4)):
                    with self.subTest(version=version, creation=creation, height=height, challenge=challenge.hex()):
                        self.check(script, challenge, expected, version=version, creation=creation, height=height)

    def test_appendix_c_limit_can_consume_the_last_byte(self):
        self.assertEqual(SAMPLE_IN_BALL_BYTES, 221)
        stream = b'\xff' * (SAMPLE_IN_BALL_BYTES - CHALLENGE_WEIGHT) + bytes(range(CHALLENGE_WEIGHT))
        for signed, search, find_by_borrow in ((False, False, False), (True, False, False),
                                               (True, True, False), (True, True, True)):
            script = sample_from_stream_script(signed=signed, search=search, find_by_borrow=find_by_borrow)
            expected = pack([-1] * CHALLENGE_WEIGHT + [0] * (256 - CHALLENGE_WEIGHT), signed=signed)
            with self.subTest(signed=signed, search=search, find_by_borrow=find_by_borrow):
                self.check(script, stream, expected)
                self.check(script, b'\xff' + stream[:-1], None)
                self.check(script, b'\xff' * SAMPLE_IN_BALL_BYTES, None)
                self.check(script, stream[:-1], None)

    def test_search_skips_one_above_each_selection_index(self):
        first = DEGREE - CHALLENGE_WEIGHT
        draws = b''.join(bytes((i + 1, i)) for i in range(first, DEGREE - 1)) + b'\xff'
        stream = (b'\x55' * CHALLENGE_SIGN_BYTES + draws).ljust(SAMPLE_IN_BALL_BYTES, b'\x00')
        coefficients = [0] * first + [(-1 if i % 2 == 0 else 1) for i in range(CHALLENGE_WEIGHT)]
        code = push(stream) + sample_from_stream_script(signed=True, search=True, find_by_borrow=True)
        code += push(pack(coefficients, signed=True)) + asm('OP_EQUAL')
        script = Script()
        script.append_data(code)
        self.assertTrue(Context(script=script, tx_version=1).evaluate())


if __name__ == '__main__':
    unittest.main()

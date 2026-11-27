"""Check rejection and neighboring valid cases in complete synthetic spends."""

from dataclasses import replace
from hashlib import shake_256
from itertools import product
import os
import unittest

from challenge_script import sample_from_stream_script
from check_chain_gang import _case
from fips204 import CHALLENGE_SIGN_BYTES, CHALLENGE_WEIGHT, SAMPLE_IN_BALL_BYTES, _pack, _use_hint
from hint_script import apply_hints_with_packed_rounding_script
from ntt_script import COEFFICIENT_BYTES, POLYNOMIAL_BYTES, _LANE_BYTES, transform_script
from polynomial import DEGREE, MODULUS, ntt
from shake_script import shake256_script
from signature_script import (
    GAMMA1, HINT_ROWS, HINT_WEIGHT_LIMIT, RESPONSE_BITS, RESPONSE_COUNT, RESPONSE_NORM_LIMIT,
    hint_decode_script, packed_response_check_script,
)
from fourthgraph.benchmark.validation import Node
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.script import asm, encode_num, number


# (transaction version, previous output creation height, spend height).
ERAS = ((1, 1, 2), (2, 1, 4), (2, 3, 4))


def _indices(indices):
    return b''.join((abs(index) | (0x8000 if index < 0 else 0)).to_bytes(2, 'little') for index in indices)


def _residues(values):
    return b''.join(value.to_bytes(COEFFICIENT_BYTES, 'little') for value in values)


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cookie = os.environ.get('REGTEST_COOKIE')
        cls.node = Node(os.environ.get('REGTEST_URL', 'http://127.0.0.1:18443'), cookie) if cookie else None

    def check_cases(self, kernel, cases, *, rejection='Error evaluating the script'):
        for label, values, expected in cases:
            parent, spend = _case(kernel, values, expected)
            for version, creation, height in ERAS:
                with self.subTest(case=label, version=version, creation=creation, height=height):
                    candidate = replace(spend, version=version)
                    args = dict(spend_height=height, activation_height=3, utxo_heights=(creation,))
                    if expected is None:
                        with self.assertRaisesRegex(ValueError, rejection):
                            validate_at_heights(candidate, (parent,), **args)
                    else:
                        validate_at_heights(candidate, (parent,), **args)
                    if self.node:
                        self.assertEqual(self.node.verdicts(candidate, (parent,), **args), [expected is not None])

    def test_fixed_width_numeric_overflow(self):
        # The sign bit consumes one bit at each production serialization width.
        for width in (COEFFICIENT_BYTES, _LANE_BYTES, HINT_ROWS * _LANE_BYTES):
            limit = 1 << (8 * width - 1)
            cases = []
            for sign in (-1, 1):
                boundary = (limit - 1) | (limit if sign < 0 else 0)
                cases.append((f'{width} bytes, sign {sign}, fits',
                              (encode_num(sign * (limit - 1)),), boundary.to_bytes(width, 'little')))
                cases.append((f'{width} bytes, sign {sign}, sign bit overflow', (encode_num(sign * limit),), None))
                cases.append((f'{width} bytes, sign {sign}, one extra byte', (encode_num(sign * 2 * limit),), None))
            self.check_cases(number(width) + asm('OP_NUM2BIN'), cases,
                             rejection='OP_NUM2BIN failed, number does not fit the size')

    def test_ntt_rejects_noncanonical_or_out_of_range_coefficients(self):
        values = [MODULUS - 1] + [0] * (DEGREE - 2) + [MODULUS - 1]
        valid = _residues(values)
        cases = [('largest canonical residue', (valid,), _residues(ntt(values))),
                 ('missing coefficient byte', (valid[:-1],), None),
                 ('extra coefficient byte', (valid + b'\x00',), None)]
        sign_bit = 1 << (8 * COEFFICIENT_BYTES - 1)
        for index, value in product((0, DEGREE - 1), (MODULUS, MODULUS + 1, sign_bit - 1, sign_bit, sign_bit + 1)):
            changed = values.copy()
            changed[index] = value
            cases.append((f'noncanonical residue {value} at {index}', (_residues(changed),), None))
        self.check_cases(transform_script(compact=True), cases)

    def test_packed_response_norm_and_length(self):
        minimum = GAMMA1 - RESPONSE_NORM_LIMIT + 1
        maximum = GAMMA1 + RESPONSE_NORM_LIMIT - 1
        values = [minimum, maximum] * (RESPONSE_COUNT * DEGREE // 2)
        valid = _pack(values, RESPONSE_BITS)
        cases = [('inside both norm limits', (valid,), valid),
                 ('truncated packed response', (valid[:-1],), None),
                 ('oversized packed response', (valid + b'\x00',), None)]
        positions = (0, 1, 63, 64, DEGREE - 1, DEGREE, len(values) - 1)
        outside = (0, minimum - 1, maximum + 1, (1 << RESPONSE_BITS) - 1)
        for index, value in product(positions, outside):
            changed = values.copy()
            changed[index] = value
            cases.append((f'response value {value} at {index}', (_pack(changed, RESPONSE_BITS),), None))
        self.check_cases(packed_response_check_script(), cases)

    def test_hint_wire_endpoints_padding_and_order(self):
        empty = bytes(HINT_WEIGHT_LIMIT + HINT_ROWS)
        max_indices = range(DEGREE - HINT_WEIGHT_LIMIT, DEGREE)
        valid_max = bytes(max_indices) + bytes((0, 0, 0, HINT_WEIGHT_LIMIT))
        across_rows = b'\xff\xff' + bytes(HINT_WEIGHT_LIMIT - 2) + bytes((1, 1, 1, 2))
        cases = [
            ('empty hints', (empty,), b''),
            ('highest weight and last index', (valid_max,), _indices(3 * DEGREE + i for i in max_indices)),
            ('same byte index in different rows', (across_rows,), _indices((DEGREE - 1, 4 * DEGREE - 1))),
            ('hint vector too short', (empty[:-1],), None),
            ('hint vector too long', (empty + b'\x00',), None),
        ]
        bad_endpoints = ((0, 0, 0, HINT_WEIGHT_LIMIT + 1), (0, 0, 0, 255), (1, 0, 0, 0))
        for endpoints in bad_endpoints:
            cases.append((f'out of range endpoints {endpoints}', (bytes(HINT_WEIGHT_LIMIT) + bytes(endpoints),), None))
        for label, used in (('duplicate index', b'\xff\xff'), ('descending indices', b'\xff\xfe')):
            cases.append((label, (used + bytes(HINT_WEIGHT_LIMIT - 2) + bytes((2, 2, 2, 2)),), None))
        for padding in (1, 0x80):
            cases.append((f'nonzero padding byte {padding}',
                          (bytes(HINT_WEIGHT_LIMIT - 1) + bytes((padding,)) + bytes(HINT_ROWS),), None))
        self.check_cases(hint_decode_script(sparse=True), cases)

    def test_sparse_hint_index_and_split_bounds(self):
        count = HINT_ROWS * DEGREE
        residues = bytes(HINT_ROWS * POLYNOMIAL_BYTES)
        last_hint = _indices((count - 1,))
        last_digit = _use_hint(0, True)
        cases = [('empty sparse indices', (residues, b''), _pack([0] * count, 6)),
                 ('last index is in bounds', (residues, last_hint), _pack([0] * (count - 1) + [last_digit], 6)),
                 ('partial index', (residues, last_hint[:-1]), None),
                 ('too many sparse indices', (residues, _indices(range(HINT_WEIGHT_LIMIT + 1))), None),
                 ('short residue vector', (residues[:-1], last_hint), None),
                 ('long residue vector', (residues + b'\x00', last_hint), None)]
        kernel = apply_hints_with_packed_rounding_script()
        self.check_cases(kernel, cases)
        for indices, reason in (((-count, -1), 'n negative'), ((count, (1 << 15) - 1), 'n out of range')):
            cases = [(f'sparse index {index} out of bounds', (residues, _indices((index,))), None)
                     for index in indices]
            self.check_cases(kernel, cases, rejection=f'OP_SPLIT failed, {reason}')

    def test_sampler_exhaustion_and_length(self):
        signs = b'\xff' * CHALLENGE_SIGN_BYTES
        candidate_count = SAMPLE_IN_BALL_BYTES - CHALLENGE_SIGN_BYTES
        draws = b'\xff' * (candidate_count - CHALLENGE_WEIGHT) + bytes(range(CHALLENGE_WEIGHT))
        valid = signs + draws
        expected = b'\x81' * CHALLENGE_WEIGHT + bytes(DEGREE - CHALLENGE_WEIGHT)
        cases = [('last available draw is accepted', (valid,), expected),
                 ('missing final selection', (signs + b'\xff' + draws[:-1],), None),
                 ('no acceptable draw', (signs + b'\xff' * candidate_count,), None),
                 ('truncated SHAKE prefix', (valid[:-1],), None),
                 ('oversized SHAKE prefix', (valid + b'\x00',), None)]
        self.check_cases(sample_from_stream_script(signed=True, search=True, find_by_borrow=True), cases)

    def test_shake_checks_rate_boundary_length(self):
        message = bytes(range(136))
        output = shake_256(message).digest(137)
        cases = [('exact rate block', (message,), output),
                 ('missing rate byte', (message[:-1],), None),
                 ('extra rate byte', (message + b'\x00',), None)]
        self.check_cases(shake256_script(len(message), len(output)), cases)


if __name__ == '__main__':
    unittest.main()

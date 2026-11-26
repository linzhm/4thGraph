"""Check ML-DSA-44 Script decoding against the Python FIPS reference."""

import json
from pathlib import Path
import unittest

from fips204 import _hints, _pack, _unpack
from mldsa import test_only_vector
from polynomial import DEGREE, MODULUS
from signature_script import (
    CHALLENGE_BYTES, GAMMA1, HINT_WEIGHT_LIMIT, RESPONSE_BITS, RESPONSE_COUNT,
    RESPONSE_NORM_LIMIT, RESPONSE_PACKED_BYTES, hint_decode_script,
    response_decode_script, signature_decode_script,
)
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import Input, Output, Transaction, hash256
from tx_engine import Context, Script, Tx


def _context(code):
    script = Script()
    script.append_data(code)
    return Context(script=script, tx_version=1)


def _hint_encoding(rows):
    indices = bytearray()
    endpoints = bytearray()
    for row in rows:
        indices.extend(row)
        endpoints.append(len(indices))
    return bytes(indices).ljust(HINT_WEIGHT_LIMIT, b'\x00') + bytes(endpoints)


def _bitmap(hints):
    return b''.join(sum(1 << index for index in row).to_bytes(DEGREE // 8, 'little') for row in hints)


def _residues(coefficients):
    return b''.join((coefficient % MODULUS).to_bytes(3, 'little') for coefficient in coefficients)


def _stack_items(stack):
    return [bytes(stack[index]) for index in range(stack.size())]


class SignatureScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vector_path = Path(__file__).resolve().parents[1] / 'versions/v0.1.0' / 'deterministic.json'
        vector = json.loads(vector_path.read_text())
        _, cls.signature = test_only_vector(
            bytes.fromhex(vector['seed_test_only']), bytes.fromhex(vector['message']),
            context=bytes.fromhex(vector['context']),
        )

    def test_openssl_signature_decodes_to_python_values(self):
        hint_offset = CHALLENGE_BYTES + RESPONSE_PACKED_BYTES
        challenge = self.signature[:CHALLENGE_BYTES]
        encoded_response = self.signature[CHALLENGE_BYTES:hint_offset]
        response = _unpack(encoded_response, RESPONSE_COUNT * DEGREE, RESPONSE_BITS)
        z = _residues(GAMMA1 - value for value in response)
        hints = _bitmap(_hints(self.signature[hint_offset:]))

        code = push(b'main') + push(b'alt') + asm('OP_TOALTSTACK') + push(self.signature)
        context = _context(code + signature_decode_script())
        self.assertTrue(context.evaluate_core())
        self.assertEqual(_stack_items(context.get_stack()), [b'main', challenge, z, hints])
        self.assertEqual(_stack_items(context.get_altstack()), [b'alt'])

    def test_hint_boundaries(self):
        for rows in (
            ((), (), (), ()),
            ((0, 1, 127, 128, 255), (), (7, 8), (254, 255)),
            ((), tuple(range(80)), (), ()),
        ):
            with self.subTest(rows=rows):
                encoded = _hint_encoding(rows)
                expected = _bitmap(_hints(encoded))
                code = push(encoded) + hint_decode_script() + push(expected) + asm('OP_EQUAL')
                self.assertTrue(_context(code).evaluate())

    def test_noncanonical_hints(self):
        malformed = (
            bytes(80) + bytes((81, 81, 81, 81)),
            bytes(80) + bytes((1, 0, 1, 1)),
            _hint_encoding(((0, 0), (), (), ())),
            _hint_encoding(((4, 3), (), (), ())),
            bytes(79) + b'\x80' + bytes(4),
        )
        for encoded in malformed:
            with self.subTest(encoded=encoded.hex()):
                self.assertIsNone(_hints(encoded))
                code = push(encoded) + hint_decode_script() + asm('OP_DROP OP_1')
                self.assertFalse(_context(code).evaluate(quiet=True))

    def test_response_norm_and_signature_length(self):
        response = [0] * (RESPONSE_COUNT * DEGREE)
        response[0], response[-1] = RESPONSE_NORM_LIMIT - 1, 1 - RESPONSE_NORM_LIMIT
        encoded = _pack([GAMMA1 - value for value in response], RESPONSE_BITS)
        code = push(encoded) + response_decode_script() + push(_residues(response)) + asm('OP_EQUAL')
        self.assertTrue(_context(code).evaluate())

        for invalid in (RESPONSE_NORM_LIMIT, -RESPONSE_NORM_LIMIT):
            response[DEGREE] = invalid
            encoded = _pack([GAMMA1 - value for value in response], RESPONSE_BITS)
            code = push(encoded) + response_decode_script() + asm('OP_DROP OP_1')
            self.assertFalse(_context(code).evaluate(quiet=True))

        for signature in (self.signature[:-1], self.signature + b'\x00'):
            code = push(signature) + signature_decode_script() + asm('OP_2DROP OP_DROP OP_1')
            self.assertFalse(_context(code).evaluate(quiet=True))

    def test_explicit_chronicle_context(self):
        decoded = _context(push(self.signature) + signature_decode_script())
        self.assertTrue(decoded.evaluate_core())
        expected_hash = hash256(b''.join(_stack_items(decoded.get_stack())))
        lock = signature_decode_script() + asm('OP_CAT OP_CAT OP_HASH256')
        lock += push(expected_hash) + asm('OP_EQUAL')
        # Complete synthetic inputs exercise the decoder under explicit era
        # flags. The test output only compares the decoded fixture bytes.
        funding = Transaction((Input(b'\x54' * 32, 0),), (Output(1000, lock),), version=1)
        parent = Tx.parse(funding.serialize())
        invalid = self.signature[:-1] + b'\xff'
        regimes = ((14999, 14998), (15000, 14999), (15001, 15000))
        for version in (1, 2):
            for spend_height, utxo_height in regimes:
                for signature in (self.signature, invalid):
                    valid = signature == self.signature
                    with self.subTest(version=version, spend_height=spend_height, valid=valid):
                        spend = Transaction(
                            (Input(funding.txid_wire(), 0, push(signature)),),
                            (Output(900, asm('OP_1')),), version=version,
                        )
                        candidate = Tx.parse(spend.serialize())
                        args = ([parent], spend_height, 15000, [(funding.txid(), 0, utxo_height)])
                        if valid:
                            candidate.validate_with_chronicle_context(*args, consensus_only=True)
                        else:
                            with self.assertRaises(ValueError):
                                candidate.validate_with_chronicle_context(*args, consensus_only=True)


if __name__ == '__main__':
    unittest.main()

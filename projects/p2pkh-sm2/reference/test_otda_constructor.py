"""Constructor byte equivalence and complete spending through both engines."""
from dataclasses import replace
import unittest
from unittest.mock import patch

from assemble import SCHEDULED_TEMPLATE_VERSION, TEMPLATE_VERSIONS
from generate_otda_constructor import generate
from p2pkh_sm2 import _otda_pattern, current_input_unlock, locking_script_from_public_key, sign_input
from fourthgraph.benchmark.validation import chain_verdict
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.transaction import Input, Output, Transaction
from sighash import authorization
from sm2 import USER_ID, encode_public, fixture_sign, mul
from test_node import check_node
from test_sighash import chain_check


class ConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scalars = (1, 7)
        cls.keys = tuple(encode_public(mul(scalar)) for scalar in cls.scalars)
        cls.locks = tuple(locking_script_from_public_key(key) for key in cls.keys)
        cls.funding = tuple(
            Transaction((Input(bytes([i + 1]) * 32, 0),), (Output(10_000, lock),))
            for i, lock in enumerate(cls.locks)
        )
        cls.inputs = tuple(Input(parent.txid_wire(), 0) for parent in cls.funding)
        cls.destinations = tuple(Output(9_900, lock) for lock in reversed(cls.locks))
        cls.native = Output(9_800, b'\x51')

    def test_frozen_program_is_reproducible_and_matches_lock(self):
        for version in TEMPLATE_VERSIONS:
            with self.subTest(version=version):
                pattern = _otda_pattern(version)
                self.assertEqual(generate(version), pattern.program)
                self.assertEqual(evaluate(pattern.program), (list(pattern.fixed_parts), []))
                for key in self.keys:
                    lock = locking_script_from_public_key(key, version=version)
                    fields = pattern.match(lock)
                    self.assertEqual(len(fields), 1)
                    self.assertEqual(b''.join((pattern.fixed_parts[0], *fields, pattern.fixed_parts[1])), lock)
                    self.assertIsNone(pattern.match(lock[:-1]))
                    self.assertIsNone(pattern.match(lock[:-1] + b'\x51'))
        self.assertLess(len(_otda_pattern(SCHEDULED_TEMPLATE_VERSION).program), len(_otda_pattern().program))

    def sign_modes(self, tx, flag, expected, *, funding=None):
        funding = self.funding if funding is None else funding
        tx_raw, tx_compact = tx, tx
        for index, (parent, key, scalar) in enumerate(zip(funding, self.keys, self.scalars, strict=True)):
            auth = authorization(tx, index, parent.outputs[0].value, flag)
            signature = fixture_sign(scalar, auth.message, 71 + index)

            def signer(message, user_id):
                self.assertEqual((message, user_id), (auth.message, USER_ID))
                return signature

            args = index, parent.serialize(), key, signer, flag
            tx_raw = sign_input(tx_raw, *args, compress_otda=False)
            tx_compact = sign_input(tx_compact, *args)
            raw, compact = tx_raw.inputs[index].script, tx_compact.inputs[index].script
            self.assertEqual(compact != raw, expected[index])
            if expected[index]:
                self.assertLess(len(compact), len(raw))
            self.assertEqual(evaluate(raw), ([auth.preimage, key, signature], []))
            self.assertEqual(evaluate(compact), ([auth.preimage, key, signature], []))
            self.assertEqual(
                compact, current_input_unlock(tx, index, parent.outputs[0].value, key, signature,
                                              flag),
            )
        self.assertTrue(chain_verdict(tx_raw, funding))
        self.assertTrue(chain_verdict(tx_compact, funding))
        for index in range(len(tx.inputs)):
            check_node(tx_raw, funding, index)
            check_node(tx_compact, funding, index)
        return tx_compact

    def test_all_single_and_literal_fallbacks(self):
        sm2 = self.destinations
        mixed = (self.native, sm2[1])
        for version, flag, outputs, expected in (
            (2, 0x61, sm2, (True, True)),
            (2, 0x61, mixed, (True, True)),
            (2, 0xe1, (*sm2, replace(self.native, value=1)), (True, True)),
            (2, 0x63, sm2, (True, True)),
            (2, 0xe3, sm2, (True, True)),
            (2, 0xe3, mixed, (False, True)),
            (2, 0x63, sm2[:1], (True, False)),
            (2, 0x62, sm2, (False, False)),
            (2, 0xe2, sm2, (False, False)),
            (2, 0x61, (self.native, self.native), (False, False)),
            (1, 0x61, sm2, (False, False)),
            (2, 0x41, sm2, (False, False)),
        ):
            with self.subTest(version=version, flag=hex(flag), output_sizes=tuple(len(out.script) for out in outputs)):
                self.sign_modes(Transaction(self.inputs, outputs, version=version), flag, expected)

    def test_reconstruction_preserves_output_commitments(self):
        tx = Transaction(self.inputs, self.destinations)
        signed = self.sign_modes(tx, 0x61, (True, True))
        changed = replace(signed, outputs=(replace(signed.outputs[0], value=9_899), signed.outputs[1]))
        check_node(changed, self.funding, 0, False)
        chain_check(changed, self.funding, 0, False)

        single = self.sign_modes(tx, 0x63, (True, True))
        changed = replace(single, outputs=(single.outputs[0], replace(single.outputs[1], value=9_899)))
        check_node(changed, self.funding, 0)
        check_node(changed, self.funding, 1, False)
        chain_check(changed, self.funding, 1, False)

    def test_two_lock_versions_can_be_spent_and_rebuilt_together(self):
        new_lock = locking_script_from_public_key(self.keys[1], version=SCHEDULED_TEMPLATE_VERSION)
        funding = (self.funding[0], replace(self.funding[1], outputs=(Output(10_000, new_lock),)))
        inputs = tuple(Input(parent.txid_wire(), 0) for parent in funding)
        tx = Transaction(inputs, (self.destinations[1], Output(9_800, new_lock), Output(1, b'\x51')))
        for flag in (0x61, 0xe1, 0x63, 0xe3):
            with self.subTest(flag=hex(flag)):
                signed = self.sign_modes(tx, flag, (True, True), funding=funding)
                self.assertLess(max(len(item.script) for item in signed.inputs), 30_000)
                for index in range(len(inputs)):
                    check_node(signed, funding, index, old_output=True)
                changed = replace(signed, outputs=tuple(reversed(signed.outputs)))
                check_node(changed, funding, 1, flag in (0x63, 0xe3))
                if flag in (0x61, 0xe1):
                    chain_check(changed, funding, 1, False)

    def test_larger_constructor_falls_back_to_literal_encoding(self):
        tx = Transaction(self.inputs, self.destinations)
        pattern = _otda_pattern()
        oversized = replace(pattern, program=pattern.program + bytes(len(tx.serialize())))
        with patch('p2pkh_sm2._otda_pattern', return_value=oversized):
            self.sign_modes(tx, 0x61, (False, False))

    def test_all_lock_versions_reconstruct_in_one_preimage(self):
        versions = TEMPLATE_VERSIONS[-2:]
        funding = tuple(
            replace(parent, outputs=(Output(10_000, locking_script_from_public_key(key, version=version)),))
            for parent, key, version in zip(self.funding, self.keys, versions, strict=True)
        )
        inputs = tuple(Input(parent.txid_wire(), 0) for parent in funding)
        outputs = tuple(
            Output(1_000, locking_script_from_public_key(self.keys[0], version=version))
            for version in TEMPLATE_VERSIONS
        )
        tx = Transaction(inputs, outputs)
        signed = self.sign_modes(tx, 0x61, (True, True), funding=funding)
        # Copying any complete output verbatim would exceed this bound.
        self.assertLess(max(len(item.script) for item in signed.inputs), min(len(out.script) for out in outputs))
        for index in range(len(inputs)):
            check_node(signed, funding, index, old_output=True)

    def test_reconstruction_requires_chronicle_before_signing(self):
        tx = Transaction(self.inputs, self.destinations)

        def signer(*args):
            self.fail("inactive functional unlocking invoked the signer")

        args = tx, 0, self.funding[0].serialize(), self.keys[0], signer
        with self.assertRaisesRegex(ValueError, 'Chronicle sighash is disabled'):
            sign_input(*args, 0x61, chronicle_active=False)
        with self.assertRaisesRegex(ValueError, 'requires an active Chronicle context'):
            sign_input(*args, 0x41, chronicle_active=False, compress_otda=True)

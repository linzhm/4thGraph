"""Exhaustive bounded acceptance checks for the repository Lamport profiles."""
from dataclasses import replace
from hashlib import sha256
from itertools import product
import os
import unittest

from engines import chain_valid
from fixtures import INVALID_PREVOUT_CASES, cases, mode_fixture, test_secret
from forth_verifier import committed_verifier_code
from lamport import OneTimeSigner, public_key, sign_digest, verify_digest
from payment import sign_spend
from script import (
    committed_locking_script, compact_forth_committed_locking_script, forth_committed_locking_script, locking_script,
)
from fourthgraph.bsv.evaluate import evaluate, ScriptError
from fourthgraph.bsv.script import number, push
from fourthgraph.bsv.transaction import Input, Output, Transaction
from test_node import node_check


VERSIONS = (1, 2)
PAIRING = (False, True)
COMMITTED_FACTORIES = (committed_locking_script, forth_committed_locking_script, compact_forth_committed_locking_script)
# The twelve byte values and commitment groups are specified in docs/spec.md.
ALL = {0x41, 0x61, 0xc1, 0xe1}
NONE = {0x42, 0x62, 0xc2, 0xe2}
SINGLE = {0x43, 0x63, 0xc3, 0xe3}
ANYONECANPAY = {0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3}
MODES = sorted(ALL | NONE | SINGLE)
EDITS = (
    'unchanged', 'other_output', 'other_sequence', 'other_outpoint', 'own_sequence',
    'locktime', 'version', 'pairing_changed', 'paired_output',
)
LEGACY_CASES = frozenset("""
    valid output_amount supplied_output_amount output_script supplied_output_script
    locktime supplied_locktime version supplied_version sequence supplied_sequence
    outpoint_index supplied_outpoint_index outpoint_hash supplied_outpoint_hash
    short_pre long_pre wrong_flag wrong_script_code wrong_amount short_sig long_sig
    wrong_sig swapped_blocks wrong_key wrong_digest extra_item missing_item
    multi_input output_order other_sequence other_outpoint
""".split())


def edited_payments(signed, parents):
    """Keep the original witness on the signing input for every edit."""
    other, owned = parents
    first, current = signed.inputs
    first_output = signed.outputs[0]
    new_other = replace(other, locktime=1)
    yield 'unchanged', signed, parents
    yield 'other_output', replace(
        signed, outputs=(replace(first_output, value=first_output.value - 1), *signed.outputs[1:]),
    ), parents
    yield 'other_sequence', replace(signed, inputs=(replace(first, sequence=1), current)), parents
    yield 'other_outpoint', replace(
        signed, inputs=(replace(first, txid=new_other.txid_wire()), current),
    ), (new_other, owned)
    yield 'own_sequence', replace(signed, inputs=(first, replace(current, sequence=1))), parents
    yield 'locktime', replace(signed, locktime=1), parents
    yield 'version', replace(signed, version=3 - signed.version), parents
    paired = len(signed.outputs) == 2
    outputs = (first_output,) if paired else (first_output, Output(1, b'\x51'))
    yield 'pairing_changed', replace(signed, outputs=outputs), parents
    if paired:
        second = signed.outputs[1]
        yield 'paired_output', replace(signed, outputs=(first_output, replace(second, value=second.value - 1))), parents


class LamportAcceptance(unittest.TestCase):
    def test_every_commitment_selection_and_its_counterexamples(self):
        secret = test_secret(b'acceptance/commitment-slots')
        blocks = [secret[i:i+32] for i in range(0, len(secret), 32)]
        commitments = b''.join(sha256(block).digest() for block in blocks)
        self.assertEqual(public_key(secret), commitments)
        lock = locking_script(commitments, transaction=False)
        expected = set(product((0, 1), range(256), ('digest_bit', 'signature_slot', 'matching_flip')))
        visited = set()
        for choice in (0, 1):
            digest = bytes((255 * choice,)) * 32
            signature = b''.join(blocks[choice::2])
            self.assertEqual(sign_digest(secret, digest), signature)
            self.assertTrue(verify_digest(commitments, digest, signature))
            self.assertEqual(evaluate(lock, [digest, signature]), ([b'\x01'], []))
            for index in range(256):
                byte_index, bit_index = divmod(index, 8)
                changed_digest = bytearray(digest)
                changed_digest[byte_index] ^= 1 << bit_index
                changed_digest = bytes(changed_digest)
                slot = 32 * index
                opposite = blocks[2 * index + 1 - choice]
                changed_signature = signature[:slot] + opposite + signature[slot+32:]
                for edit, message, candidate in (
                    ('digest_bit', changed_digest, signature),
                    ('signature_slot', digest, changed_signature),
                    ('matching_flip', changed_digest, changed_signature),
                ):
                    row = (choice, index, edit)
                    with self.subTest(row=row):
                        self.assertNotIn(row, visited)
                        visited.add(row)
                        matches = edit == 'matching_flip'
                        self.assertEqual(verify_digest(commitments, message, candidate), matches)
                        if matches:
                            self.assertEqual(sign_digest(secret, message), candidate)
                            self.assertEqual(evaluate(lock, [message, candidate]), ([b'\x01'], []))
                        else:
                            with self.assertRaises(ScriptError):
                                evaluate(lock, [message, candidate])
        self.assertEqual(visited, expected)
        self.assertEqual(len(visited), 1536)

    def test_universal_payment_decisions_cover_the_declared_domain(self):
        self.check_payment_domain(locking_script)

    def test_committed_payment_decisions_cover_the_declared_domain(self):
        for factory in COMMITTED_FACTORIES:
            with self.subTest(template=factory.__name__):
                self.check_payment_domain(factory)

    def test_forth_reconstructs_the_key_for_every_digest_byte(self):
        secret = test_secret(b'forth/masks')
        key = public_key(secret)
        code = committed_verifier_code()
        self.assertEqual(sha256(code).hexdigest(), '2099467370ba8b0fcf533d5c997e33256ee0251fd0548fc3c69557e8ac95a73b')
        uniform = (bytes([value]) * 32 for value in range(256))
        for digest in (*uniform, bytes(range(224, 256))):
            with self.subTest(digest=digest.hex()):
                proof = bytearray()
                for slot in range(256):
                    selected = (digest[slot // 8] >> (slot % 8)) & 1
                    start = 64 * slot
                    pair = secret[start:start+64]
                    proof += (pair[32:] + sha256(pair[:32]).digest() if selected
                              else pair[:32] + sha256(pair[32:]).digest())
                self.assertEqual(evaluate(code, [bytes(proof), digest]), ([sha256(key).digest()], []))

    @unittest.skipUnless(os.environ.get('REGTEST_COOKIE'), 'requires BSV Node regtest')
    def test_committed_chronicle_activation_boundary(self):
        shapes = [(mode, paired) for mode in MODES for paired in ((False, True) if mode in SINGLE else (True,))]
        self.assertEqual(len(shapes), 16)
        cases = product(COMMITTED_FACTORIES, VERSIONS, shapes, ((False, 1), (True, 1), (True, 3)))
        for factory, version, (mode, paired), (chronicle, height) in cases:
            with self.subTest(template=factory.__name__, version=version, mode=hex(mode), paired=paired,
                              chronicle=chronicle, height=height):
                _, parents, tx = mode_fixture(mode, paired=paired, version=version, lock_factory=factory)
                self.assertEqual(node_check(tx, parents[1], 1, chronicle=chronicle, funding_height=height),
                                 chronicle or not bool(mode & 0x20))

    def check_payment_domain(self, lock_factory):
        expected = {
            (version, paired, mode, edit)
            for version, paired, mode, edit in product(VERSIONS, PAIRING, MODES, EDITS)
            if paired or edit != 'paired_output'
        }
        allowed = {
            'unchanged': set(MODES),
            'other_output': NONE | SINGLE,
            'other_sequence': NONE | SINGLE | ANYONECANPAY,
            'other_outpoint': ANYONECANPAY,
            'own_sequence': set(),
            'locktime': set(),
            'version': set(),
            'pairing_changed': NONE,
            'paired_output': NONE,
        }
        accepted = {row for row in expected if row[2] in allowed[row[3]]}
        self.assertEqual((len(expected), len(accepted)), (408, 168))
        visited = set()
        for version, paired, mode in product(VERSIONS, PAIRING, MODES):
            _, parents, signed = mode_fixture(mode, paired=paired, version=version,
                                              lock_factory=lock_factory)
            for edit, candidate, prevouts in edited_payments(signed, parents):
                row = (version, paired, mode, edit)
                with self.subTest(row=row):
                    self.assertIn(row, expected)
                    self.assertNotIn(row, visited)
                    visited.add(row)
                    self.assertEqual(chain_valid(candidate, prevouts), row in accepted, 'chain-gang')
                    if os.environ.get('REGTEST_COOKIE'):
                        self.assertEqual(node_check(candidate, prevouts[1], 1), row in accepted, 'BSV Node')
        self.assertEqual(visited, expected)

    def test_committed_proof_binds_every_selected_secret_and_sibling(self):
        for factory in COMMITTED_FACTORIES:
            with self.subTest(template=factory.__name__):
                self.check_committed_proof(factory)

    def check_committed_proof(self, factory):
        _, parents, signed = mode_fixture(0x41, lock_factory=factory)
        (preimage, proof, mode), _ = evaluate(signed.inputs[1].script)
        self.assertEqual(len(proof), 16384)
        self.assertEqual(mode, b'')

        def check(candidate, valid):
            tx = signed.with_script(1, push(preimage) + push(candidate) + number(0))
            self.assertEqual(chain_valid(tx, parents), valid)
            if os.environ.get('REGTEST_COOKIE'):
                self.assertEqual(node_check(tx, parents[1], 1), valid)

        check(proof, True)
        for slot in range(512):
            with self.subTest(slot=slot, selected_secret=slot % 2 == 0):
                offset = 32 * slot
                check(proof[:offset] + bytes([proof[offset] ^ 1]) + proof[offset+1:], False)
        check(proof[:-1], False)
        check(proof + b'\0', False)

    def test_committed_2in_2out_and_fresh_key_preflight(self):
        for factory, mode in product(COMMITTED_FACTORIES, (0x41, 0x61)):
            with self.subTest(template=factory.__name__, mode=hex(mode)):
                signers = [OneTimeSigner(test_secret(bytes([mode, index]))) for index in range(2)]
                keys = [signer.public_key for signer in signers]
                funding = tuple(
                    Transaction((Input(bytes([index + 1]) * 32, 0),),
                                (Output(1000, factory(key)),))
                    for index, key in enumerate(keys)
                )
                fresh_locks = tuple(factory(public_key(test_secret(bytes([mode, index]))))
                                    for index in (2, 3))
                tx = Transaction(tuple(Input(parent.txid_wire(), 0) for parent in funding),
                                 tuple(Output(900, lock) for lock in fresh_locks))
                for lock_factory in (locking_script, *COMMITTED_FACTORIES):
                    reused = replace(tx, outputs=(Output(900, lock_factory(keys[0])), tx.outputs[1]))
                    with self.assertRaisesRegex(ValueError, 'fresh Lamport key'):
                        sign_spend(reused, 0, funding[0].serialize(), keys[0], signers[0].sign, sighash=mode)
                for index, (parent, signer) in enumerate(zip(funding, signers, strict=True)):
                    tx = sign_spend(tx, index, parent.serialize(), signer.public_key, signer.sign, sighash=mode)
                self.assertTrue(chain_valid(tx, funding))
                if os.environ.get('REGTEST_COOKIE'):
                    for index, parent in enumerate(funding):
                        self.assertTrue(node_check(tx, parent, index))

    def test_legacy_cases_match_the_declared_inventory(self):
        visited = set()
        for name, tx, parents, index, fixture_verdict in cases():
            with self.subTest(name=name):
                self.assertNotIn(name, visited)
                visited.add(name)
                expected = name in {'valid', 'multi_input'}
                self.assertEqual(fixture_verdict, expected)
                self.assertEqual(chain_valid(tx, parents, expect_bad_prevout=name in INVALID_PREVOUT_CASES),
                                 expected, 'chain-gang')
                if os.environ.get('REGTEST_COOKIE'):
                    self.assertEqual(node_check(tx, parents[index], index), expected, 'BSV Node')
        self.assertEqual(visited, LEGACY_CASES)
        self.assertEqual(len(visited), 32)


if __name__ == '__main__':
    unittest.main()

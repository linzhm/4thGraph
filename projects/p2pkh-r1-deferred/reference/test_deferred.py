"""Reference and chain-gang checks. Fixture scalars are public test keys."""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from tx_engine import Script, Tx, TxIn, TxOut

from compare_forth import comparison
from deferred import (
    ACTIVATION_SIGHASH, COMPANION_CODE, DIRECT_TYPES, SCRIPT_CODE, activate_input, funding_output,
    funding_output_from_owner_hash, recognize, target_output, target_output_from_owner_hash,
)
from fixed_templates import LEGACY_TEMPLATE_VERSION, TEMPLATE_VERSION
from generate_vectors import RELEASE_TEMPLATE, TEMPLATE, artifacts
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import CHRONICLE, SIGHASH_TYPES, Input, Output, Transaction, hash256, preimage_forkid
from wallet import sign_payment
from p2pkh_r1 import public_key_hash160


def fixture_key(scalar):
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    encoded = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    return key, encoded


def fixture_signature(key, digest):
    der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def engine_script(raw):
    script = Script()
    script.append_data(raw)
    return script


def engine_tx(tx):
    converted = Tx(tx.version, [
        TxIn(x.txid[::-1].hex(), x.vout, engine_script(x.script), x.sequence) for x in tx.inputs
    ], [TxOut(x.value, engine_script(x.script)) for x in tx.outputs], tx.locktime)
    if converted.serialize() != tx.serialize():
        raise AssertionError('chain-gang transaction serialization differs')
    return converted


def fixture(*, target_r1_version=TEMPLATE_VERSION, optimization=None):
    key, public_key = fixture_key(1)
    _, second_public_key = fixture_key(2)
    recipients = (funding_output(100_000, public_key, target_r1_version=target_r1_version, optimization=optimization),
                  funding_output(120_000, second_public_key, target_r1_version=target_r1_version,
                                 optimization=optimization))
    target_outputs = (target_output(100_000, public_key, target_r1_version=target_r1_version),
                      target_output(120_000, second_public_key, target_r1_version=target_r1_version))
    sponsor = Output(10_000, asm('OP_1'))
    change = Output(8_000, asm('OP_1'))
    funding = Transaction((Input(b'\xf0' * 32, 0),), (*recipients, sponsor))
    unsigned = Transaction(
        tuple(Input(funding.txid_wire(), n) for n in range(3)), (*target_outputs, change),
    )
    return key, public_key, second_public_key, funding, unsigned


def activation_fixture(funding, unsigned):
    first = activate_input(unsigned, 0, funding.serialize())
    return activate_input(first, 1, funding.serialize())


def mode_activations(funding, unsigned):
    for flag in sorted(SIGHASH_TYPES):
        tx = replace(unsigned, version=2 if flag & CHRONICLE else 1)
        tx = activate_input(tx, 0, funding.serialize())
        yield flag, activate_input(tx, 1, funding.serialize(), sighash=flag)


def wrong_activations(funding, unsigned, valid):
    previous = funding.outputs[1]
    changed_targets = (
        ('wrong amount', replace(unsigned.outputs[1], value=previous.value - 1)),
        ('wrong recipient', replace(unsigned.outputs[0], value=previous.value)),
    )
    for label, target in changed_targets:
        tx = replace(unsigned, outputs=(unsigned.outputs[0], target, unsigned.outputs[2]))
        original = preimage_forkid(tx, 1, previous.value, SCRIPT_CODE, ACTIVATION_SIGHASH)
        yield label, tx.with_script(1, push(original)), 1
        yield label + ' with stale preimage', tx.with_script(1, valid.inputs[1].script), 1
    tx = replace(unsigned, outputs=unsigned.outputs[:1])
    original = preimage_forkid(tx, 1, previous.value, SCRIPT_CODE, ACTIVATION_SIGHASH)
    yield 'missing output', tx.with_script(1, push(original)), 1
    original = preimage_forkid(unsigned, 1, previous.value, SCRIPT_CODE, 0x41)
    yield 'wrong sighash', unsigned.with_script(1, push(original)), 1
    yield 'extra witness item', valid.with_script(1, asm('OP_1') + valid.inputs[1].script), 1


def zero_commitment_case(funding, unsigned):
    original = funding.outputs[1]
    commitment = recognize(original)
    malformed = replace(original, script=original.script.replace(commitment.output_hash, bytes(32), 1))
    previous = replace(funding, outputs=(funding.outputs[0], malformed, funding.outputs[2]))
    tx = replace(unsigned, inputs=tuple(replace(x, txid=previous.txid_wire()) for x in unsigned.inputs),
                 outputs=unsigned.outputs[:1])
    tx = activate_input(tx, 0, previous.serialize())
    preimage = preimage_forkid(tx, 1, malformed.value, SCRIPT_CODE, ACTIVATION_SIGHASH)
    return previous, tx.with_script(1, push(preimage))


class DeferredTests(unittest.TestCase):
    def test_forth_comparison_reproduces_report_and_script_codes(self):
        report, scripts = comparison()
        recorded = Path(__file__).with_name('forth-results.json').read_text(encoding='ascii')
        self.assertEqual(json.dumps(report, indent=2) + '\n', recorded)
        for name, script in scripts.items():
            with self.subTest(build=name):
                separator = asm('OP_CODESEPARATOR')
                self.assertTrue(script.endswith(separator + COMPANION_CODE))
                self.assertTrue(script.endswith(separator + SCRIPT_CODE))

    def test_reproduce_public_artifacts(self):
        for path, version in ((TEMPLATE, LEGACY_TEMPLATE_VERSION), (RELEASE_TEMPLATE, TEMPLATE_VERSION)):
            for name, content in artifacts(target_r1_version=version).items():
                with self.subTest(artifact=name, version=version):
                    self.assertEqual((path / name).read_text(encoding='ascii'), content)

    def test_public_metadata_and_canonical_recognition(self):
        _, public_key, second_key, funding, unsigned = fixture()
        output = funding.outputs[0]
        commitment = recognize(output, expected_key=public_key)
        self.assertIsNotNone(commitment)
        owner_hash = public_key_hash160(public_key)
        self.assertEqual(commitment.owner_hash160, owner_hash)
        self.assertEqual(commitment.target_r1_version, TEMPLATE_VERSION)
        self.assertIsNone(commitment.public_key)
        self.assertEqual(funding_output_from_owner_hash(output.value, owner_hash), output)
        self.assertEqual(target_output_from_owner_hash(output.value, owner_hash), unsigned.outputs[0])
        self.assertEqual(recognize(output, expected_owner_hash=owner_hash), commitment)
        self.assertEqual(commitment.script_hash, sha256(unsigned.outputs[0].script).digest())
        self.assertEqual(commitment.output_hash, hash256(unsigned.outputs[0].serialize()))
        self.assertEqual(output.script[1:21], owner_hash)
        self.assertEqual(output.script[22:54], commitment.script_hash)
        self.assertNotIn(public_key, output.script)
        self.assertEqual(len(output.script), 1435)
        self.assertEqual(len(unsigned.outputs[0].script), 46302)
        self.assertIsNone(recognize(output, expected_key=second_key))
        self.assertIsNone(recognize(replace(output, value=output.value + 1)))
        for offset in (0, 1, 22, 54, output.script.index(commitment.output_hash)):
            raw = bytearray(output.script)
            raw[offset] ^= 1
            self.assertIsNone(recognize(replace(output, script=bytes(raw))))
        with self.assertRaises(ValueError):
            funding_output(output.value, b'\x04' + bytes(64))

    def test_legacy_full_key_output_is_recognized_and_activates(self):
        _, public_key, _, funding, unsigned = fixture(target_r1_version=LEGACY_TEMPLATE_VERSION)
        output = funding.outputs[0]
        raw = push(public_key) + output.script[21:]
        self.assertEqual(sha256(raw).hexdigest(), 'e606096dc6008a9b0c4bbe082aebeaf480aa4c6277c78400469c7acce9dbfbe7')
        previous = replace(output, script=raw)
        commitment = recognize(previous, expected_key=public_key)
        self.assertEqual(commitment.public_key, public_key)
        self.assertEqual(commitment.target_r1_version, LEGACY_TEMPLATE_VERSION)
        original = replace(funding, outputs=(previous, *funding.outputs[1:]))
        tx = replace(unsigned, inputs=tuple(replace(i, txid=original.txid_wire()) for i in unsigned.inputs))
        engine_tx(activation_fixture(original, tx)).validate([engine_tx(original)])

    def test_preflight_rejects_mismatch(self):
        _, _, _, funding, unsigned = fixture()
        wrong = replace(unsigned, outputs=tuple(reversed(unsigned.outputs)))
        with self.assertRaisesRegex(ValueError, 'activation output'):
            activate_input(wrong, 0, funding.serialize())
        with self.assertRaisesRegex(ValueError, 'same-index'):
            activate_input(replace(unsigned, outputs=()), 0, funding.serialize())
        with self.assertRaisesRegex(ValueError, 'outpoint'):
            activate_input(unsigned, 0, replace(funding, locktime=1).serialize())

    def test_complete_batch_and_r1_spend_in_chain_gang(self):
        key, public_key, _, funding, unsigned = fixture()
        activation = activation_fixture(funding, unsigned)
        self.assertEqual([len(x.script) for x in activation.inputs], [160, 160, 0])
        self.assertEqual(activation.outputs, unsigned.outputs)
        engine_funding, engine_activation = engine_tx(funding), engine_tx(activation)
        engine_activation.validate([engine_funding])
        with TemporaryDirectory() as tmp:
            payment = sign_payment(
                engine_activation, 0, [TxOut(99_000, engine_script(asm('OP_1')))], 1_000,
                public_key, lambda digest: fixture_signature(key, digest), Path(tmp) / 'wallet.sqlite',
            )
        payment.validate([engine_activation])

        altered = replace(Transaction.parse(payment.serialize()), outputs=(Output(98_000, asm('OP_1')),))
        with self.assertRaises((ValueError, RuntimeError)):
            engine_tx(altered).validate([engine_activation])

    def test_activation_constraints_in_chain_gang(self):
        _, _, _, funding, unsigned = fixture()
        valid = activation_fixture(funding, unsigned)
        engine_funding = engine_tx(funding)
        for label, tx, _ in wrong_activations(funding, unsigned, valid):
            if not tx.inputs[0].script:
                tx = activate_input(tx, 0, funding.serialize())
            with self.subTest(label=label), self.assertRaises((ValueError, RuntimeError)):
                engine_tx(tx).validate([engine_funding])

    def test_all_modes_keep_the_forkid_output_constraint(self):
        _, _, _, funding, unsigned = fixture()
        parent = engine_tx(funding)
        for flag, signed in mode_activations(funding, unsigned):
            with self.subTest(flag=hex(flag)):
                witness = signed.inputs[1].script
                self.assertEqual(len(witness), 160 if flag in DIRECT_TYPES else 197)
                engine_tx(signed).validate([parent])
                # Keep input zero valid so rejection is attributable to input one.
                outputs = (signed.outputs[0], replace(signed.outputs[1], value=119_999), signed.outputs[2])
                altered = replace(signed, outputs=outputs).with_script(0, b'')
                altered = activate_input(altered, 0, funding.serialize())
                with self.assertRaises((ValueError, RuntimeError)):
                    engine_tx(altered).validate([parent])
                with self.assertRaises(ValueError):
                    activate_input(replace(unsigned, outputs=unsigned.outputs[:1]), 1, funding.serialize(), sighash=flag)
                if flag not in DIRECT_TYPES:
                    wrong_digest = witness[:2] + bytes([witness[2] ^ 1]) + witness[3:]
                    with self.assertRaises((ValueError, RuntimeError)):
                        engine_tx(signed.with_script(1, wrong_digest)).validate([parent])

    def test_malformed_zero_commitment_fails_in_chain_gang(self):
        _, _, _, funding, unsigned = fixture()
        malformed, tx = zero_commitment_case(funding, unsigned)
        self.assertIsNone(recognize(malformed.outputs[1]))
        with self.assertRaises((ValueError, RuntimeError)):
            engine_tx(tx).validate([engine_tx(malformed)])


if __name__ == '__main__':
    unittest.main()

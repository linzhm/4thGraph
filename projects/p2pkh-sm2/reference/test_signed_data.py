"""Verify SignedData payment interop without changing the locking template."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from p2pkh_sm2 import locking_script_from_public_key, sign_input
from signed_data import signed_data_signer, verify_signed_data
from sm2 import N, USER_ID, encode_public, fixture_sign, mul, sm3
from test_sm2 import der, der_signature, fixture, public_pem
from test_sighash import chain_check
from fourthgraph.bsv.transaction import Input, Output, Transaction


SKI = der(0x80, b'\xa7' * 20)
ISSUER = der(0x30, der(0x31, der(0x30, bytes.fromhex('0603550403') + der(0x0c, b'Test issuer'))))
ISSUER_AND_SERIAL = der(0x30, ISSUER + der(0x02, b'\x01'))
OTHER_ISSUER_AND_SERIAL = der(0x30, ISSUER + der(0x02, b'\x02'))
SM3 = der(0x30, bytes.fromhex('06082a811ccf550183110500'))
SM2 = der(0x30, bytes.fromhex('06092a811ccf5501822d010500'))
SM2_WITH_SM3 = der(0x30, bytes.fromhex('06082a811ccf550183750500'))
DATA_OID = bytes.fromhex('060a2a811ccf550601040201')
SIGNED_DATA_OID = bytes.fromhex('060a2a811ccf550601040202')
TEST_KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
FIXTURE_IDENTIFIER = bytes.fromhex(
    '303e303931173015060355040a130e42535620536372697074204c6162'
    '311e301c06035504031315496e646570656e64656e7420476f205369676e6572020101'
)
PYTHON_SIGNER = Path(__file__).resolve().parent / 'interop' / 'python-signer' / 'sm2_signed_data_signer.py'


def signed_data(signature, *, attached=None, sid=ISSUER_AND_SERIAL, version=2,
                outer_version=1, algorithm=SM2, signed_attrs=b'', unsigned_attrs=b'',
                metadata=b'', content_oid=DATA_OID, outer_oid=SIGNED_DATA_OID,
                digest_algorithms=SM3, signer_digest=SM3, extra_signers=b'', include_signer=True):
    content = content_oid
    if attached is not None:
        content += der(0xa0, der(0x04, attached))
    signer = (der(0x02, bytes((version,))) + sid + signer_digest + signed_attrs + algorithm
              + der(0x04, signature) + unsigned_attrs)
    signers = b''.join(sorted((der(0x30, signer) if include_signer else b'', extra_signers)))
    body = (der(0x02, bytes((outer_version,))) + der(0x31, digest_algorithms)
            + der(0x30, content) + metadata + der(0x31, signers))
    return der(0x30, outer_oid + der(0xa0, der(0x30, body)))


class SignedDataTests(unittest.TestCase):
    def test_template_witness_is_identical_for_both_sighash_families(self):
        key, _, parent, tx, _, _ = fixture()
        for flag, attached in ((0x41, False), (0x61, True)):
            with self.subTest(flag=hex(flag), attached=attached):
                def sign_raw(message, user_id):
                    return fixture_sign(1, message, 2, user_id)

                def sign_envelope(message, user_id):
                    return signed_data(der_signature(sign_raw(message, user_id)),
                                       attached=message if attached else None)

                funding = parent.serialize()
                direct = sign_input(tx, 0, funding, key, sign_raw, flag)
                adapter = signed_data_signer(sign_envelope, key, signer_identifier=ISSUER_AND_SERIAL)
                adapted = sign_input(tx, 0, funding, key, adapter, flag)
                self.assertEqual(adapted.serialize(), direct.serialize())
                chain_check(adapted, (parent,), 0)

    def test_openssl_signer_interoperates(self):
        with tempfile.TemporaryDirectory() as directory:
            private_key = str(Path(directory) / 'test-only.pem')
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'SM2', '-out', private_key], check=True)
            key = subprocess.check_output(['openssl', 'pkey', '-in', private_key, '-pubout', '-outform', 'DER'])[-65:]

            def sign_envelope(message, user_id):
                path = Path(directory) / 'message'
                path.write_bytes(message)
                signature = subprocess.check_output([
                    'openssl', 'pkeyutl', '-sign', '-rawin', '-digest', 'sm3', '-inkey', private_key,
                    '-pkeyopt', 'distid:' + user_id.decode('ascii'), '-in', str(path),
                ])
                return signed_data(signature, attached=message)

            parent = Transaction((Input(b'\xa7' * 32, 0),), (Output(1000, locking_script_from_public_key(key)),))
            tx = Transaction((Input(parent.txid_wire(), 0),), (Output(900, b'\x51'),))
            adapter = signed_data_signer(sign_envelope, key, signer_identifier=ISSUER_AND_SERIAL)
            adapted = sign_input(tx, 0, parent.serialize(), key, adapter)
            chain_check(adapted, (parent,), 0)

    def test_rejects_wrong_authorization_or_container(self):
        message = bytes(range(32))
        key = encode_public(mul(1))
        signature = der_signature(fixture_sign(1, message, 2))
        good = signed_data(signature)
        digest_attribute = der(0x30, bytes.fromhex('06092a864886f70d010904') + der(0x31, der(0x04, sm3(message))))
        attribute_signature = der_signature(fixture_sign(1, der(0x31, digest_attribute), 2))
        variants = {
            'attached content differs': signed_data(signature, attached=bytes(32)),
            'wrong detached message': signed_data(der_signature(fixture_sign(1, bytes(32), 2))),
            'wrong SM2 ID': signed_data(der_signature(fixture_sign(1, message, 2, b'other ID'))),
            'wrong key': signed_data(der_signature(fixture_sign(2, message, 2))),
            'wrong serial': signed_data(signature, sid=OTHER_ISSUER_AND_SERIAL),
            'SKI': signed_data(signature, sid=SKI),
            'signed attributes': signed_data(attribute_signature, attached=message,
                                              signed_attrs=der(0xa0, digest_attribute)),
            'wrong algorithm': signed_data(signature, algorithm=SM3),
            'invalid signature DER': signed_data(bytes.fromhex('300702020001020101')),
            'extra signature data': signed_data(signature + b'\x00'),
            'trailing data': good + b'\x00',
            'truncated content': good[:-1],
        }
        for name, envelope in variants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                signed_data_signer(lambda *_: envelope, key,
                                   signer_identifier=ISSUER_AND_SERIAL)(message, USER_ID)

    def test_provider_identifier_requires_valid_configuration(self):
        key = encode_public(mul(1))
        for identifier in (SKI, der(0x30, ISSUER + der(0x02, b'\x00')),
                           der(0x30, ISSUER + der(0x02, b'\x00\x01'))):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                signed_data_signer(lambda *_: None, key, signer_identifier=identifier)


class SignedDataSignerChecks:
    def request(self, message, detached=False):
        arguments = [*self.command, '-message', message.hex(), '-key', TEST_KEY]
        if detached:
            arguments.append('-detached')
        return self.read_envelope(arguments)

    def read_envelope(self, arguments):
        response = json.loads(subprocess.check_output(arguments))
        self.assertEqual(set(response), {
            'envelope_hex', 'public_key_hex', 'signer_identifier_hex', 'signer_version',
        })
        self.assertEqual(bytes.fromhex(response['public_key_hex']), encode_public(mul(int(TEST_KEY, 16))))
        self.assertEqual(bytes.fromhex(response['signer_identifier_hex']), FIXTURE_IDENTIFIER)
        self.assertEqual(response['signer_version'], 2)
        return bytes.fromhex(response['envelope_hex'])

    def test_independent_signed_data_provider(self):
        key = encode_public(mul(int(TEST_KEY, 16)))
        for flag, detached in ((0x41, False), (0x61, True)):
            with self.subTest(flag=hex(flag), detached=detached):
                parent = Transaction((Input(b'\xa7' * 32, 0),),
                                     (Output(1000, locking_script_from_public_key(key)),))
                tx = Transaction((Input(parent.txid_wire(), 0),), (Output(900, b'\x51'),))

                def provider(message, user_id):
                    self.assertEqual(user_id, USER_ID)
                    envelope = self.request(message, detached)
                    trusted = {FIXTURE_IDENTIFIER: (key, user_id)}
                    if detached:
                        with self.assertRaisesRegex(ValueError, 'detached content'):
                            verify_signed_data(envelope, trusted)
                    self.assertEqual(verify_signed_data(
                        envelope, trusted, detached_content=message if detached else None,
                    ), message)
                    return envelope

                adapter = signed_data_signer(provider, key, signer_identifier=FIXTURE_IDENTIFIER)
                adapted = sign_input(tx, 0, parent.serialize(), key, adapter, flag)
                chain_check(adapted, (parent,), 0)
                if os.environ.get('REGTEST_COOKIE'):
                    from test_node import check_node
                    check_node(adapted, (parent,), 0)

    def test_openssl_verifies_independent_signer_output(self):
        key = encode_public(mul(int(TEST_KEY, 16)))
        message = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'public.pem').write_bytes(public_pem(key))
            (path / 'message').write_bytes(message)
            for detached in (False, True):
                with self.subTest(detached=detached):
                    adapter = signed_data_signer(
                        lambda payload, _: self.request(payload, detached),
                        key, signer_identifier=FIXTURE_IDENTIFIER,
                    )
                    (path / 'signature').write_bytes(der_signature(adapter(message, USER_ID)))
                    subprocess.run([
                        'openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', 'public.pem',
                        '-rawin', '-digest', 'sm3', '-pkeyopt', 'distid:' + USER_ID.decode('ascii'),
                        '-in', 'message', '-sigfile', 'signature',
                    ], cwd=directory, check=True, capture_output=True)

    def test_independent_signer_rejects_invalid_arguments(self):
        cases = {
            'missing key': ('-message', '01'),
            'missing message': ('-key', TEST_KEY),
            'empty message': ('-message', '', '-key', TEST_KEY),
            'non-hex message': ('-message', 'gg', '-key', TEST_KEY),
            'whitespace in message hex': ('-message', '00 ff', '-key', TEST_KEY),
            'non-hex key': ('-message', '01', '-key', 'gg' * 32),
            'short key': ('-message', '01', '-key', '01'),
            'long key': ('-message', '01', '-key', TEST_KEY + '01'),
            'zero scalar': ('-message', '01', '-key', '00' * 32),
            'scalar n minus one': ('-message', '01', '-key', f'{N - 1:064x}'),
            'scalar n': ('-message', '01', '-key', f'{N:064x}'),
            'invalid detached flag': ('-message', '01', '-key', TEST_KEY, '-detached=maybe'),
        }
        for case, arguments in cases.items():
            with self.subTest(case=case):
                result = subprocess.run([*self.command, *arguments], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
                self.assertTrue(result.stderr)

    def test_long_content_and_cli_aliases(self):
        message = bytes(range(128))
        trusted = {FIXTURE_IDENTIFIER: (encode_public(mul(int(TEST_KEY, 16))), USER_ID)}
        for detached in (False, True):
            with self.subTest(detached=detached):
                envelope = self.read_envelope([
                    *self.command, f'--message={message.hex()}', f'--key={TEST_KEY}',
                    f'--detached={str(detached).lower()}',
                ])
                expected_content = message if detached else None
                if detached:
                    with self.assertRaisesRegex(ValueError, 'detached content'):
                        verify_signed_data(envelope, trusted)
                self.assertEqual(verify_signed_data(
                    envelope, trusted, detached_content=expected_content,
                ), message)


class PythonSignedDataSignerTests(SignedDataSignerChecks, unittest.TestCase):
    command = (sys.executable, str(PYTHON_SIGNER))


@unittest.skipUnless(os.environ.get('SM2_SIGNED_DATA_SIGNER'),
                     'set SM2_SIGNED_DATA_SIGNER to the Rust signer executable')
class IndependentSignedDataTests(SignedDataSignerChecks, unittest.TestCase):
    command = (os.environ.get('SM2_SIGNED_DATA_SIGNER'),)


if __name__ == '__main__':
    unittest.main()

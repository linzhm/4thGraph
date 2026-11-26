"""Complete ML-DSA-44 payments across Chronicle activation contexts."""

from dataclasses import replace
from hashlib import sha256
from itertools import product
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from fips204 import SIGNATURE_BYTES
from mldsa import test_only_vector as make_test_vector
from payment import authorization, sign_spend
from script import _historical_lock, _v02_lock, locking_script
from sdk_adapter import recognize
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.transaction import SIGHASH_TYPES, Input, Output, Transaction


TEST_SEED = bytes(range(32))
TRANSACTION_VERSIONS = (1, 2)
PAYMENT_MODES = (
    ('forkid', 'all', (0x41, 0xc1)),
    ('forkid', 'none', (0x42, 0xc2)),
    ('forkid', 'single', (0x43, 0xc3)),
    ('otda', 'all', (0x61, 0xe1)),
    ('otda', 'none', (0x62, 0xe2)),
    ('otda', 'single', (0x63, 0xe3)),
)
HEIGHT_CONTEXTS = ((2, (1, 1)), (4, (1, 1)), (4, (1, 3)), (4, (3, 1)), (4, (3, 3)))
VARIANTS = ('original', 'last_output_value', 'locktime', 'signature_byte')
# Independently listed positive variants in each output-commitment mode.
VALID_VARIANTS = {
    ('all', True): {'original'},
    ('none', True): {'original', 'last_output_value'},
    ('single', True): {'original'},
    ('single', False): {'original', 'last_output_value'},
}


class PaymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = os.environ.get('ML_DSA_OPENSSL', 'openssl')
        cls.public_key, _ = make_test_vector(TEST_SEED, bytes(32), openssl=cls.openssl)
        funding = Transaction((Input(b'\x61' * 32, 0),), (Output(10_000, locking_script(cls.public_key)),))
        other = Transaction((Input(b'\x42' * 32, 0),), (Output(1_000, b'\x51'),))
        cls.parents = other, funding
        cls.funding_raw = funding.serialize()

    def signer(self, digest):
        public_key, signature = make_test_vector(TEST_SEED, digest, openssl=self.openssl)
        self.assertEqual(public_key, self.public_key)
        return signature

    def payment(self, flag, version, paired):
        inputs = tuple(Input(parent.txid_wire(), 0) for parent in self.parents)
        outputs = (Output(500, b'\x51'), Output(10_400, b'\x51')) if paired else (Output(10_900, b'\x51'),)
        tx = Transaction(inputs, outputs, version=version)
        return sign_spend(tx, 1, self.funding_raw, self.public_key, self.signer, sighash=flag)

    def check_spend(self, spend, expected, height, creation_heights):
        arguments = {'spend_height': height, 'activation_height': 3, 'utxo_heights': creation_heights}
        if expected:
            validate_at_heights(spend, self.parents, **arguments)
        else:
            with self.assertRaisesRegex(ValueError, 'Error evaluating the script'):
                validate_at_heights(spend, self.parents, **arguments)
        if executable := os.environ.get('ML_DSA_BSVS'):
            self.check_lean(executable, spend, self.parents, expected, height, creation_heights)
        if cookie_path := os.environ.get('REGTEST_COOKIE'):
            self.check_node(cookie_path, spend, self.parents, expected, height, creation_heights)

    def check_lean(self, executable, spend, parents, expected, height, creation_heights):
        prevouts = []
        for txin, parent, creation in zip(spend.inputs, parents, creation_heights, strict=True):
            prevout = parent.outputs[txin.vout]
            prevouts.append(dict(txid=parent.txid_wire()[::-1].hex(), vout=txin.vout, height=creation,
                                 satoshis=prevout.value, script=prevout.script.hex()))
        with TemporaryDirectory(prefix='ml-dsa-lean-') as directory:
            tx_file = Path(directory, 'tx.hex')
            prevouts_file = Path(directory, 'prevouts.json')
            tx_file.write_text(spend.serialize().hex())
            prevouts_file.write_text(json.dumps(prevouts))
            result = subprocess.run([
                executable, 'eval', '--tx', f'@{tx_file}', '--prevouts', f'@{prevouts_file}',
                '--consensus', 'true', '--spend-height', str(height), '--config', 'sv-regtest',
                '--genesis-height', '1', '--chronicle-height', '3',
            ], check=True, capture_output=True, text=True, timeout=60)
        verdict = json.loads(result.stdout)
        self.assertEqual(verdict['verdict'], 'valid' if expected else 'invalid', verdict)

    def check_node(self, cookie_path, spend, parents, expected, height, creation_heights):
        from base64 import b64encode
        from urllib.request import Request, urlopen

        index = len(parents) - 1
        prevout = parents[index].outputs[spend.inputs[index].vout]
        creation = creation_heights[index]
        flags = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19))
        flags |= (1 << 20) if height >= 3 else 0
        flags |= (1 << 21) if creation >= 3 else 0
        request = dict(tx=spend.serialize().hex(), n=index, flags=flags, reportflags=True,
                       txo=dict(lock=prevout.script.hex(), value=prevout.value, height=creation))
        data = json.dumps(dict(jsonrpc='1.0', id='ml-dsa', method='verifyscript',
                               params=[[request], False, 5000])).encode()
        cookie = b64encode(Path(cookie_path).read_bytes().strip()).decode()
        headers = {'Authorization': 'Basic ' + cookie, 'Content-Type': 'application/json'}
        url = os.environ.get('REGTEST_URL', 'http://127.0.0.1:18443')
        with urlopen(Request(url, data, headers), timeout=30) as response:
            reply = json.load(response)
        self.assertIsNone(reply['error'])
        result = reply['result'][0]
        self.assertEqual(result['flags'], flags)
        self.assertEqual(result['result'], 'ok' if expected else 'error', result)

    def test_sighash_activation_and_output_eras(self):
        self.assertEqual({flag for _, _, flags in PAYMENT_MODES for flag in flags}, SIGHASH_TYPES)
        modes = tuple((family, outputs, flag, paired)
                      for family, outputs, flags in PAYMENT_MODES for flag in flags
                      for paired in ((True, False) if outputs == 'single' else (True,)))
        shapes = tuple((flag, paired) for _, _, flag, paired in modes)
        domain = set(product(TRANSACTION_VERSIONS, shapes, HEIGHT_CONTEXTS, VARIANTS))
        self.assertEqual(len(shapes), 16)
        self.assertEqual(len(set(shapes)), 16)
        self.assertEqual(len(domain), 640)
        visited = set()
        matched = {True: 0, False: 0}
        for version, (family, outputs, flag, paired) in product(TRANSACTION_VERSIONS, modes):
            spend = self.payment(flag, version, paired)
            auth = authorization(spend, 1, 10_000, flag)
            self.assertEqual(auth.companion, family == 'otda' and not paired)
            witness = spend.inputs[1].script
            # The one-byte selector follows the signature push. Flip one challenge bit.
            signature = witness[-SIGNATURE_BYTES - 1:-1]
            self.assertEqual(witness, auth.witness(signature))
            changed_signature = bytes((signature[0] ^ 1,)) + signature[1:]
            last = replace(spend.outputs[-1], value=spend.outputs[-1].value - 1)
            variants = {
                'original': spend,
                'last_output_value': replace(spend, outputs=(*spend.outputs[:-1], last)),
                'locktime': replace(spend, locktime=1),
                'signature_byte': spend.with_script(1, auth.witness(changed_signature)),
            }
            self.assertEqual(set(variants), set(VARIANTS))
            for (height, creation), (variant, transaction) in product(HEIGHT_CONTEXTS, variants.items()):
                with self.subTest(version=version, sighash=hex(flag), paired=paired, height=height,
                                  creation=creation, variant=variant):
                    case = (version, (flag, paired), (height, creation), variant)
                    self.assertIn(case, domain)
                    self.assertNotIn(case, visited)
                    visited.add(case)
                    expected = (family == 'forkid' or height >= 3) and variant in VALID_VARIANTS[outputs, paired]
                    self.check_spend(transaction, expected, height, creation)
                    matched[expected] += 1

        self.assertEqual(visited, domain)
        self.assertEqual(matched, {True: 216, False: 424})

    def test_invalid_signer_response(self):
        signed = self.payment(0x41, 2, True)
        unsigned = signed.with_script(1, b'')
        with self.assertRaisesRegex(ValueError, 'invalid ML-DSA-44 signature'):
            sign_spend(unsigned, 1, self.funding_raw, self.public_key, lambda digest: b'')

    def test_historical_locks_remain_recognizable_and_spendable(self):
        earlier = (
            (_historical_lock(self.public_key, compact=False),
             '3905094cfb41cad09a939cfe8c8264400faf264a6db0cb30851c7dbdefd93295'),
            (_historical_lock(self.public_key, compact=True),
             '899fc5fd435d593e37fe00af3c834d814d57af4abcd63bf632d0e7870c7fc77f'),
            (_v02_lock(self.public_key),
             'f579d4c51555f5e5b7820250af52c091112827b8ae9daa2c6500b37fa3832a2e'),
        )
        for previous_lock, fingerprint in earlier:
            self.assertEqual(sha256(previous_lock).hexdigest(), fingerprint)
            self.assertLess(len(locking_script(self.public_key)), len(previous_lock))
            self.assertEqual(recognize(previous_lock, self.public_key), {'template': 'pure-ml-dsa-44'})
            funding = replace(self.parents[1], outputs=(Output(10_000, previous_lock),))
            parents = self.parents[0], funding
            inputs = tuple(Input(parent.txid_wire(), 0) for parent in parents)
            tx = Transaction(inputs, (Output(10_900, b'\x51'),), version=2)
            for flag in (0x41, 0x61, 0x63):
                with self.subTest(previous_lock_bytes=len(previous_lock), sighash=hex(flag)):
                    spend = sign_spend(tx, 1, funding.serialize(), self.public_key, self.signer, sighash=flag)
                    validate_at_heights(spend, parents, spend_height=4, activation_height=3, utxo_heights=(1, 3))
                    if cookie_path := os.environ.get('REGTEST_COOKIE'):
                        self.check_node(cookie_path, spend, parents, True, 4, (1, 3))

    def test_unrecognized_lock_is_rejected_before_signing(self):
        funding = replace(self.parents[1], outputs=(Output(10_000, b'\x51'),))
        unsigned = Transaction((Input(funding.txid_wire(), 0),), (Output(9_900, b'\x51'),))

        def unexpected_signer(_):
            self.fail('an unrecognized funding output reached the external signer')

        with self.assertRaisesRegex(ValueError, 'canonical template'):
            sign_spend(unsigned, 0, funding.serialize(), self.public_key, unexpected_signer)


if __name__ == '__main__':
    unittest.main()

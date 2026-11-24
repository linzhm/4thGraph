"""Complete ML-DSA-44 payments across Chronicle activation contexts."""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from mldsa import test_only_vector as make_test_vector
from payment import authorization, sign_spend
from script import locking_script
from shared.chain_gang import validate_at_heights
from shared.transaction import CHRONICLE, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_TYPES, Input, Output, Transaction


TEST_SEED = bytes(range(32))


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
        auth = authorization(tx, 1, 10_000, flag)
        self.assertEqual(auth.companion, bool(flag & CHRONICLE) and flag & 31 == SIGHASH_SINGLE and not paired)
        return sign_spend(tx, 1, self.funding_raw, self.public_key, self.signer, sighash=flag)

    def check_spend(self, spend, expected, height, creation_heights):
        arguments = {'spend_height': height, 'activation_height': 3, 'utxo_heights': creation_heights}
        if expected:
            validate_at_heights(spend, self.parents, **arguments)
        else:
            with self.assertRaises((RuntimeError, ValueError)):
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
        for version in (1, 2):
            for flag in sorted(SIGHASH_TYPES):
                for paired in (True, False) if flag & 31 == SIGHASH_SINGLE else (True,):
                    with self.subTest(version=version, sighash=hex(flag), paired=paired):
                        spend = self.payment(flag, version, paired)
                        for height, creation in ((2, (1, 1)), (4, (1, 1)), (4, (1, 3)), (4, (3, 3))):
                            with self.subTest(height=height, creation=creation):
                                self.check_spend(spend, height >= 3 or not flag & CHRONICLE, height, creation)

                        last = replace(spend.outputs[-1], value=spend.outputs[-1].value - 1)
                        changed = replace(spend, outputs=(*spend.outputs[:-1], last))
                        self.check_spend(changed, not paired or flag & 31 == SIGHASH_NONE, 4, (3, 3))
                        self.check_spend(replace(spend, locktime=1), False, 4, (3, 3))

    def test_invalid_signer_response(self):
        signed = self.payment(0x41, 2, True)
        unsigned = signed.with_script(1, b'')
        with self.assertRaisesRegex(ValueError, 'invalid ML-DSA-44 signature'):
            sign_spend(unsigned, 1, self.funding_raw, self.public_key, lambda digest: b'')

    def test_unrecognized_lock_is_rejected_before_signing(self):
        funding = replace(self.parents[1], outputs=(Output(10_000, b'\x51'),))
        unsigned = Transaction((Input(funding.txid_wire(), 0),), (Output(9_900, b'\x51'),))

        def unexpected_signer(_):
            self.fail('an unrecognized funding output reached the external signer')

        with self.assertRaisesRegex(ValueError, 'canonical template'):
            sign_spend(unsigned, 0, funding.serialize(), self.public_key, unexpected_signer)


if __name__ == '__main__':
    unittest.main()

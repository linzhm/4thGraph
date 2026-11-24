"""BSV Node verifyscript replay against explicit prevouts on isolated regtest."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import requests

from test_deferred import (
    activation_fixture, engine_script, engine_tx, fixture, fixture_signature, mode_activations,
    wrong_activations, zero_commitment_case,
)
from shared.script import asm
from shared.transaction import CHRONICLE, Transaction
from tx_engine import TxOut
from wallet import sign_payment


class NodeTests(unittest.TestCase):
    def assert_node_result(self, tx, parent, index, expected, *, chronicle=True, funding_height=3):
        prevout = parent.outputs[tx.inputs[index].vout]
        cookie = Path(os.environ['REGTEST_COOKIE']).read_text().strip().split(':', 1)
        flags = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19))
        if chronicle:
            flags |= 1 << 20
            if funding_height >= 2:
                flags |= 1 << 21
        request = dict(tx=tx.serialize().hex(), n=index, flags=flags, reportflags=True,
                       txo=dict(lock=prevout.script.hex(), value=prevout.value, height=funding_height))
        response = requests.post(os.environ.get('REGTEST_URL', 'http://127.0.0.1:18443'),
                                 auth=tuple(cookie), timeout=30,
                                 json=dict(jsonrpc='1.0', id=1, method='verifyscript',
                                           params=[[request], False, 5000]))
        response.raise_for_status()
        reply = response.json()
        self.assertIsNone(reply.get('error'), reply)
        result = reply['result'][0]
        self.assertEqual(result['flags'] & flags, flags, result)
        self.assertEqual(result['result'], expected, result)

    def test_activation_and_r1_spend(self):
        key, public_key, _, funding, unsigned = fixture()
        activation = activation_fixture(funding, unsigned)
        for index in range(3):
            self.assert_node_result(activation, funding, index, 'ok')
        with TemporaryDirectory() as tmp:
            payment = sign_payment(
                engine_tx(activation), 0, [TxOut(99_000, engine_script(asm('OP_1')))], 1_000,
                public_key, lambda digest: fixture_signature(key, digest), Path(tmp) / 'wallet.sqlite',
            )
        self.assert_node_result(Transaction.parse(payment.serialize()), activation, 0, 'ok')

    def test_rejected_activations(self):
        _, _, _, funding, unsigned = fixture()
        valid = activation_fixture(funding, unsigned)
        for label, tx, index in wrong_activations(funding, unsigned, valid):
            with self.subTest(label=label):
                self.assert_node_result(tx, funding, index, 'error')
        malformed, tx = zero_commitment_case(funding, unsigned)
        self.assert_node_result(tx, malformed, 1, 'error')

    def test_genesis_and_chronicle_activation_modes(self):
        _, _, _, funding, unsigned = fixture()
        for flag, tx in mode_activations(funding, unsigned):
            with self.subTest(flag=hex(flag)):
                self.assert_node_result(tx, funding, 1, 'ok')
                self.assert_node_result(tx, funding, 1, 'ok', funding_height=1)
                self.assert_node_result(tx, funding, 1, 'error' if flag & CHRONICLE else 'ok',
                                        chronicle=False, funding_height=1)


if __name__ == '__main__':
    unittest.main()

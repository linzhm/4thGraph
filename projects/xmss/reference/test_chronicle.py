"""Verify the XMSS payment matrix with the independent chain-gang context API."""

from dataclasses import replace
import json
import unittest

from fixtures import VECTORS, funding, unsigned_spend
from payment import authorization, current_input_unlock
from shared.chain_gang import validate_at_heights
from shared.transaction import CHRONICLE, SIGHASH_NONE


class ChronicleTests(unittest.TestCase):
    def check_spend(self, transaction, parents, expected, spend_height, utxo_heights):
        settings = dict(spend_height=spend_height, activation_height=3, utxo_heights=utxo_heights)
        if expected:
            validate_at_heights(transaction, parents, **settings)
        else:
            with self.assertRaises((RuntimeError, ValueError)):
                validate_at_heights(transaction, parents, **settings)

    def test_sighash_activation_and_mutations(self):
        fixture = json.loads(VECTORS.read_text())
        key = bytes.fromhex(fixture['public_key'])
        parents = funding(key)
        vectors = [vector for vector in fixture['vectors'] if vector['kind'] == 'payment']
        self.assertEqual(len(vectors), 32)
        for vector in vectors:
            version, flag, paired = (vector[field] for field in ('version', 'flag', 'paired'))
            with self.subTest(version=version, flag=hex(flag), paired=paired):
                spend = unsigned_spend(parents, version, paired)
                auth = authorization(spend, 1, 10_000, flag)
                signed = spend.with_script(1, current_input_unlock(auth, key, bytes.fromhex(vector['signature'])))
                for height, creation in ((2, (1, 1)), (4, (1, 1)), (4, (1, 3)), (4, (3, 3))):
                    with self.subTest(height=height, creation=creation):
                        self.check_spend(signed, parents, height >= 3 or not flag & CHRONICLE, height, creation)

                last = replace(signed.outputs[-1], value=signed.outputs[-1].value - 1)
                changed = replace(signed, outputs=(*signed.outputs[:-1], last))
                self.check_spend(changed, parents, not paired or flag & 31 == SIGHASH_NONE, 4, (3, 3))
                self.check_spend(replace(signed, locktime=1), parents, False, 4, (3, 3))


if __name__ == '__main__':
    unittest.main()

import unittest
from dataclasses import replace
from importlib.util import find_spec

import freeze_probe as probe
from shared.evaluate import evaluate
from shared.script import asm, encode_num
from shared.transaction import Input, Output, Transaction
from test_operational_token import fixture_signer
from transaction_relation import TokenState


class FreezeProbeTests(unittest.TestCase):
    def setUp(self):
        self.owner, _ = fixture_signer(11)
        self.issuer, self.sign = fixture_signer(12)
        self.state = TokenState(b"a" * 32, 640, self.owner)

    def create(self, lock_body):
        token = probe.METADATA_PREFIX + self.state.encode() + asm("OP_2DROP") + lock_body
        previous = Transaction((Input(b"t" * 32, 0),), (Output(1000, token),))
        sponsor = Transaction((Input(b"f" * 32, 0),), (Output(500_000, asm("OP_1")),))
        inputs = (Input(previous.txid_wire(), 0), Input(sponsor.txid_wire(), 0))
        return Transaction(inputs, (probe.paired_successor(previous.outputs[0]),)), previous, sponsor

    def test_statement_matches_host_across_compactsize_boundaries(self):
        for script_size in (0, 200, 65_536):
            tx, previous, _ = self.create(asm("OP_1") * script_size)
            spent = previous.outputs[0]
            material = probe.transaction_witness(tx, spent, self.sign)
            result = evaluate(material + probe.transaction_statement_script(self.issuer), checksig=lambda *_: True)
            self.assertEqual(result, (list(map(encode_num, probe.signals(tx, spent))), []))

    @unittest.skipUnless(find_spec("tx_engine"), "requires the independent chain-gang evaluator")
    def test_native_binding_checks_real_spend_and_issuer_signature(self):
        from shared.chain_gang import validate_at_heights

        # Isolate the native authentication fragment from the proof check.
        body = probe.transaction_statement_script(self.issuer) + asm("OP_2DROP OP_1")
        candidate, previous, sponsor = self.create(body)
        spent = previous.outputs[0]
        material = probe.transaction_witness(candidate, spent, self.sign)
        final = candidate.with_script(0, material)
        validate_at_heights(final, (previous, sponsor), spend_height=10, activation_height=2, utxo_heights=(3, 3))

        other = candidate.with_script(0, probe.transaction_witness(candidate, spent, fixture_signer(13)[1]))
        stale = replace(final, outputs=(replace(final.outputs[0], value=1001),))
        for rejected in (other, stale):
            with self.assertRaises(ValueError):
                validate_at_heights(rejected, (previous, sponsor), spend_height=10, activation_height=2,
                                    utxo_heights=(3, 3))

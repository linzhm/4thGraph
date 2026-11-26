"""Check the BLS12-381 residue equation, packet ABI, and actual Script spends."""

import json
from math import gcd
import unittest

from groth16_bls12381 import HOST, PACKET_BYTES, Q, QUOTIENT_ORDER, R, U, public_signals
from groth16_bls12381_replay import load_fixture, witness_controls
from groth16_replay import sign_spend
from replay import TestKeys
from shared.chain_gang import validate_at_heights
from shared.transaction import Input, Output, Transaction


class BLS12381Tests(unittest.TestCase):
    def test_residue_and_frobenius(self):
        self.assertEqual(gcd(Q + U, QUOTIENT_ORDER), R)
        value = (((11, 20), (33, 49), (55, 61)), ((72, 80), (95, 105), (112, 125)))
        self.assertEqual(HOST.power12(value, Q), HOST.frobenius12(value))

    def test_public_scalars_are_canonical(self):
        self.assertEqual(public_signals('["0",1,"19"]'), (0, 1, 19))
        for values in ([R], [True], ["00"], [-1], ["1.0"], {"x": "0"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                public_signals(json.dumps(values))

    def test_complete_spends_and_invalid_packets(self):
        verifier, ((signals, proof), (other_signals, other_proof)) = load_fixture()
        keys = TestKeys()
        script = verifier.compile(signals, keys.public["operator"])
        witness = verifier.witness(signals, proof)
        self.assertEqual(len(witness), PACKET_BYTES + 3)
        alternate = verifier.witness(other_signals, other_proof)
        with self.assertRaisesRegex(ValueError, "does not match"):
            verifier.witness(signals, other_proof)
        cases = witness_controls(witness, alternate)
        for version in (1, 2):
            parent = Transaction((Input(bytes(32), 0),), (Output(2_000_000, script),), version=version)
            unsigned = Transaction((Input(parent.txid_wire(), 0),), (Output(1_900_000, b"\x51"),), version=version)

            def verify(candidate, height):
                validate_at_heights(sign_spend(unsigned, parent, candidate, keys), (parent,),
                                    spend_height=103, activation_height=height, utxo_heights=(102,))

            for activation in (2, 1000):
                with self.subTest(version=version, activation=activation):
                    verify(witness, activation)
            for name, bad in cases.items():
                with self.subTest(version=version, name=name), self.assertRaises((ValueError, RuntimeError)):
                    verify(bad, 2)


if __name__ == "__main__":
    unittest.main()

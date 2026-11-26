"""Check the BLS12-381 residue equation, packet ABI, and actual Script spends."""

import json
from hashlib import sha256
from math import gcd
import unittest

from groth16_bls12381 import (
    AFFINE_BYTES, Curve, Dynamic, HOST, PACKET_BYTES, Q, QUOTIENT_ORDER, R, U, ScriptVerifier,
    bind_public_output, input_sources, public_output, public_packet, public_signals,
)
from groth16_bls12381_replay import load_fixture, witness_controls
from groth16_replay import sign_spend
from replay import TestKeys
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, preimage_all


def g1_json(point):
    return list((*point, 1) if point is not None else (0, 1, 0))


def g2_json(point):
    return [list(pair) for pair in (*point, (1, 0))]


def spend_fixture(lock, witness, output=None):
    parent = Transaction((Input(bytes(32), 0),), (Output(2000, lock),))
    tx = Transaction((Input(parent.txid_wire(), 0, witness),), (output or Output(1000, asm("OP_1")),))
    return parent, tx


def check_spend(parent, tx):
    validate_at_heights(tx, (parent,), spend_height=4, activation_height=2, utxo_heights=(3,))


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

    def test_input_source_encoding(self):
        self.assertEqual(input_sources('[null,"16",{"bits":128}]'), (Dynamic(), 16, Dynamic(128)))
        for invalid in ('{"bits":128}', '[true]', '[{"bits":0}]', '[{"bits":256}]', '[{"bits":true}]', '["01"]'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                input_sources(invalid)

    def test_dynamic_hybrid_and_authenticated_successor(self):
        verifier, cases = load_fixture()
        # The last two signals are equal in both real proofs.
        dynamic = (Dynamic(32), Dynamic(1), Dynamic(32), Dynamic(2), Dynamic(2))
        hybrid = dynamic[:3] + cases[0][0][3:]
        for config in (dynamic, hybrid):
            with self.subTest(config=config):
                lock = verifier.compile(config)
                packets = tuple(public_packet(config, signals) for signals, _ in cases)
                witness = tuple(verifier.witness(signals, proof, sources=config) for signals, proof in cases)
                for index, good in enumerate(witness):
                    parent, tx = spend_fixture(lock, good)
                    check_spend(parent, tx)
                    prefix = good[:-len(push(packets[index]))]
                    forged = tx.with_script(0, prefix + push(packets[1 - index]))
                    with self.assertRaises((ValueError, RuntimeError)):
                        check_spend(parent, forged)
                    other_prefix = witness[1 - index][:-len(push(packets[1 - index]))]
                    matching_msm = prefix[:-AFFINE_BYTES] + other_prefix[-AFFINE_BYTES:]
                    with self.assertRaises((ValueError, RuntimeError)):
                        check_spend(parent, tx.with_script(0, matching_msm + push(packets[1 - index])))
                if config == hybrid:
                    invalid = (*cases[0][0][:3], 0, 2)
                    with self.assertRaisesRegex(ValueError, "differs from the fixed"):
                        verifier.witness(invalid, cases[0][1], sources=config)

        lock = bind_public_output(verifier.compile(dynamic), dynamic, 1000)
        signals, proof = cases[0]
        unlock = verifier.witness(signals, proof, sources=dynamic)
        good_state = public_output(1000, public_packet(dynamic, signals))
        wrong_state = public_output(1000, public_packet(dynamic, cases[1][0]))
        for output in (good_state, wrong_state):
            parent, draft = spend_fixture(lock, b"", output)
            tx = draft.with_script(0, unlock + push(preimage_all(draft, 0, 2000)))
            if output == good_state:
                check_spend(parent, tx)
            else:
                # The preimage belongs to the real spend. Only its output
                # disagrees with the single public packet used by the proof.
                with self.assertRaises((ValueError, RuntimeError)):
                    check_spend(parent, tx)

    def test_msm_infinity_zero_and_full_field_boundary(self):
        fixture, _ = load_fixture()
        p, q = fixture.key.alpha, fixture.key.beta
        g1 = Curve(HOST)
        key = {"protocol": "groth16", "curve": "bls12381", "nPublic": 2,
               "vk_alpha_1": g1_json(p), "vk_beta_2": g2_json(q), "vk_gamma_2": g2_json(q),
               "vk_delta_2": g2_json(q), "IC": [g1_json(p), g1_json(g1.negate(p)), g1_json(p)]}
        verifier = ScriptVerifier(json.dumps(key))
        config = (Dynamic(), Dynamic(2))
        lock = verifier.compile(config)
        # Public test key with known relationships. [1 - s + t]P is the
        # VK point, and [3 - s + t]P makes the test pairing equation exact.
        for signals in ((0, 0), (1, 0), (R - 1, 2)):
            with self.subTest(signals=signals):
                s, t = signals
                proof = {**key, "pi_a": g1_json(g1.mul_host(p, (3 - s + t) % R)),
                         "pi_b": g2_json(q), "pi_c": g1_json(p)}
                witness = verifier.witness(signals, json.dumps(proof), sources=config)
                packet = push(public_packet(config, signals))
                parent, tx = spend_fixture(lock, witness)
                check_spend(parent, tx)
                proof_prefix = witness[:-len(packet)]
                public_out_of_range = tx.with_script(0, proof_prefix + push(R.to_bytes(32, "little") + bytes([t])))
                with self.assertRaises((ValueError, RuntimeError)):
                    check_spend(parent, public_out_of_range)
                if s == 1:
                    self.assertTrue(proof_prefix.endswith(bytes(AFFINE_BYTES)))
                    mismatched_claim = proof_prefix[:-1] + b"\x01" + packet
                    with self.assertRaises((ValueError, RuntimeError)):
                        check_spend(parent, tx.with_script(0, mismatched_claim))

    def test_complete_spends_and_invalid_packets(self):
        verifier, ((signals, proof), (other_signals, other_proof)) = load_fixture()
        keys = TestKeys()
        script = verifier.compile(signals, keys.public["operator"])
        self.assertEqual(sha256(script).hexdigest(),
                         "de195b42d9c4ff8b617824de2c9bcdcce3bb74aa7d5fe97d33af03569dcba406")
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

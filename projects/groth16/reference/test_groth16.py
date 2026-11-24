"""Proof, Script, wallet recognition and complete-input conformance tests."""

from dataclasses import replace
from functools import cache
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest
from urllib.request import Request, urlopen

from shared.evaluate import ScriptError, evaluate
from shared.script import asm

from descriptor import DEFAULT_EXPERIMENT, EXPERIMENTS, PROFILES, VerifierDescriptor, candidate_id
from field import ONE, Q, R, PrimeField, Tower
from fixtures import fixture, transactions
from verifier import (
    Curve, Host, Proof, check_point_host, proof_fields, unlocking_script, verify_host,
)

PROJECT = Path(__file__).resolve().parents[1]


# Finite Fp2 point on the twist, outside its prime-order subgroup.
G2_COFACTOR_POINT = (
    (2, 0),
    (
        0x18C6B864AE17DC9DA64203FFEFB966306425A7BC6AEB7C75247438372716284A4173830420CD476BA1A365B95BFCEC38,
        0x172E93DB764A8400A7D5071B6B6F5DE0DA2F0F4A063119ABCA014006B7C40A2CFE291A1924E65DB0D6D0FCFBF3BF3D5C,
    ),
)


@cache
def spend_cases():
    key, inputs, proof = fixture()
    other_key, other_inputs, other_proof = fixture(3, 17, 19)
    cases = []
    for profile in PROFILES:
        reference = VerifierDescriptor(key, inputs, profile)
        lock, _ = reference.build_lock()
        fields = reference.proof_fields(proof)
        unlock = unlocking_script(fields)
        cases.append((profile, lock, unlock, True))
        if profile not in EXPERIMENTS:
            continue
        other = VerifierDescriptor(other_key, other_inputs, profile)
        other_lock, _ = other.build_lock()
        cases.append((f"{profile}: second statement", other_lock, other.build_unlock(other_proof), True))
        cases.append((f"{profile}: different statement", other_lock, other.build_unlock(proof), False))

        invalid_fields = [
            ("noncanonical coordinate", (fields[0] + Q, *fields[1:])),
            ("negative coordinate", (-1, *fields[1:])),
            ("off-curve point", (0, *fields[1:])),
            ("small-order G1 point", (0, 2, *fields[2:])),
            ("zero residue witness", (*fields[:8], *(0,) * 12, *fields[20:])),
            ("missing element", fields[1:]),
        ]
        if profile == "gamma":
            invalid_fields.append((
                "G2 point outside subgroup", (*fields[:2], *G2_COFACTOR_POINT[0], *G2_COFACTOR_POINT[1], *fields[6:]),
            ))
        else:
            invalid_fields.append(("changed Miller slope", (*fields[:-1], (fields[-1] + 1) % Q)))
        for label, invalid in invalid_fields:
            cases.append((f"{profile}: {label}", lock, unlocking_script(invalid), False))
        cases.append((f"{profile}: extra element", lock, asm("OP_1") + unlock, False))
    return tuple(cases)


class ReferenceTests(unittest.TestCase):
    def test_host_matrix(self):
        key, inputs, proof = fixture()
        self.assertTrue(verify_host(key, inputs, proof))
        check_point_host(G2_COFACTOR_POINT, twist=True, subgroup=False)
        with self.assertRaisesRegex(ValueError, "outside prime-order subgroup"):
            check_point_host(G2_COFACTOR_POINT, twist=True)
        self.assertFalse(verify_host(key, (inputs[0] + 1, inputs[1]), proof))
        negative = replace(proof, c=Curve(Host()).negate(proof.c))
        self.assertFalse(verify_host(key, inputs, negative))
        with self.assertRaisesRegex(ValueError, "outside prime-order subgroup"):
            verify_host(key, inputs, Proof((0, 2), proof.b, proof.c))

    def test_residue_and_product_arithmetic(self):
        field = Tower(PrimeField())
        a = tuple((i + 7, i * i + 13) for i in range(6))
        b = tuple((2 * i + 1, i * i + 6) for i in range(6))

        def schoolbook(left, right):
            product = [0] * 12
            for i, (real_a, imag_a) in enumerate(left):
                for j, (real_b, imag_b) in enumerate(right):
                    real = real_a * real_b - imag_a * imag_b
                    imag = real_a * imag_b + imag_a * real_b
                    if i + j >= 6:
                        real, imag = real - imag, real + imag
                    index = (i + j) % 6 * 2
                    product[index] += real
                    product[index + 1] += imag
            return tuple((product[i] % Q, product[i + 1] % Q) for i in range(0, 12, 2))

        self.assertEqual(field.mul12(a, b), schoolbook(a, b))
        self.assertEqual(field.mul12(a, a), schoolbook(a, a))
        left, right = ((1, 2), (3, 4), (5, 0)), ((7, 8), (9, 0), (0, 13))
        self.assertEqual(
            field.mul12(a, field.join_lines(left, right)),
            field.mul_line(field.mul_line(a, left), right),
        )
        self.assertEqual(field.frobenius(a), field.power12(a, Q))
        self.assertEqual(field.mul12(a, ONE), a)

    def test_script_matrix(self):
        for label, lock, unlock, expected in spend_cases():
            with self.subTest(label=label):
                if expected:
                    self.assertEqual(evaluate(unlock + lock), ([b"\x01"], []))
                else:
                    with self.assertRaises(ScriptError):
                        evaluate(unlock + lock)

    def test_descriptor_and_checked_in_vector(self):
        key, inputs, proof = fixture()
        desc = VerifierDescriptor(key, inputs)
        lock, _ = desc.build_lock()
        funding, payment = transactions(lock, desc.build_unlock(proof), 2)
        known = json.loads((PROJECT / "template" / "vector.json").read_text())
        self.assertEqual(known["experiment"], DEFAULT_EXPERIMENT)
        self.assertEqual(bytes.fromhex(known["descriptor"]), desc.encode())
        for profile in EXPERIMENTS:
            candidate = VerifierDescriptor(key, inputs, profile)
            self.assertEqual(VerifierDescriptor.decode(candidate.encode()), candidate)
            self.assertEqual(len(candidate.build_lock()[0]), known["profiles"][profile]["locking_bytes"])
            self.assertEqual(len(candidate.build_unlock(proof)), known["profiles"][profile]["unlocking_bytes"])
        self.assertEqual(VerifierDescriptor.decode(desc.encode()), desc)
        self.assertEqual(candidate_id(lock), desc.identifier())
        self.assertTrue(desc.matches_lock(lock))
        self.assertTrue(desc.matches_prevout(payment, 0, funding))
        self.assertFalse(desc.matches_prevout(payment, 1, funding))
        self.assertFalse(desc.matches_prevout(payment, 0, replace(funding, locktime=1)))
        wrong_index = replace(payment, inputs=(replace(payment.inputs[0], vout=1),))
        self.assertFalse(desc.matches_prevout(wrong_index, 0, funding))
        self.assertEqual(candidate_id(lock[:-1] + asm("OP_0")), desc.identifier())
        self.assertFalse(desc.matches_lock(lock[:-1] + asm("OP_0")))
        self.assertFalse(desc.matches_lock(VerifierDescriptor(key, inputs, "fused").build_lock()[0]))
        self.assertIsNone(candidate_id(asm("OP_1")))
        for malformed in (desc.encode() + b"\x00", desc.encode()[:-1], b"g" + desc.encode()[1:]):
            with self.assertRaises(ValueError):
                VerifierDescriptor.decode(malformed)
        with self.assertRaises(ValueError):
            VerifierDescriptor(key, (R, inputs[1])).encode()
        self.assertEqual(known["proof_coordinates"], [f"{coordinate:096x}" for coordinate in proof_fields(proof)])
        self.assertEqual(known["locking_sha256"], sha256(lock).hexdigest())
        self.assertEqual(known["unlocking_sha256"], sha256(payment.inputs[0].script).hexdigest())
        self.assertEqual(known["funding_txid"], funding.txid())
        self.assertEqual(known["spending_txid"], payment.txid())


    def test_alpha_matches_original_scripts(self):
        key, inputs, proof = fixture()
        alpha = VerifierDescriptor(key, inputs, "alpha")
        self.assertEqual(sha256(alpha.build_lock()[0]).hexdigest(),
                         "ce1133fcac2892d29ae9859340e20765360836b5bff62b4eb02355ef4c5832c8")
        self.assertEqual(sha256(alpha.build_unlock(proof)).hexdigest(),
                         "c84947f0fccd9291c79e2589f4746f5d5bc29a9caf701b45b02fdebd0a27b7ef")


class ChainGangTests(unittest.TestCase):
    def test_complete_inputs(self):
        from shared.chain_gang import validate_at_heights

        for label, lock, unlock, expected in spend_cases():
            for version, spend_height, output_height in ((1, 2, 1), (2, 4, 1), (2, 4, 3)):
                with self.subTest(label=label, version=version, spend_height=spend_height, output_height=output_height):
                    funding, payment = transactions(lock, unlock, version)
                    parameters = dict(spend_height=spend_height, activation_height=3, utxo_heights=[output_height])
                    if expected:
                        validate_at_heights(payment, [funding], **parameters)
                    else:
                        with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                            validate_at_heights(payment, [funding], **parameters)


@unittest.skipUnless(os.environ.get("REGTEST_COOKIE"), "an isolated BSV Node RPC is required")
class NodeTests(unittest.TestCase):
    def test_complete_inputs(self):
        from base64 import b64encode

        cookie = Path(os.environ["REGTEST_COOKIE"]).read_text().strip().encode()
        authorization = "Basic " + b64encode(cookie).decode()
        flags = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19, 20, 21))
        for label, lock, unlock, expected in spend_cases():
            with self.subTest(label=label):
                funding, payment = transactions(lock, unlock, 2)
                request = {
                    "tx": payment.serialize().hex(),
                    "n": 0,
                    "flags": flags,
                    "reportflags": True,
                    "txo": {"lock": lock.hex(), "value": funding.outputs[0].value, "height": 3},
                }
                data = json.dumps({
                    "jsonrpc": "1.0", "id": "groth16", "method": "verifyscript",
                    "params": [[request], False, 5000],
                }).encode()
                url = os.environ.get("REGTEST_URL", "http://127.0.0.1:18443")
                headers = {"Authorization": authorization, "Content-Type": "application/json"}
                with urlopen(Request(url, data, headers), timeout=30) as response:
                    reply = json.load(response)
                self.assertIsNone(reply["error"])
                result = reply["result"][0]
                self.assertEqual(result["flags"] & flags, flags)
                self.assertEqual(result["result"], "ok" if expected else "error")

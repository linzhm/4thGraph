"""Cross-check an external BLS12-381 Groth16 producer against the BSV verifier."""

from functools import cache
import json
from pathlib import Path
import unittest

from descriptor import VerifierDescriptor
from fixtures import transactions
from snarkjs_adapter import load_artifacts
from verifier import verify_host


@cache
def imported():
    path = Path(__file__).resolve().parents[1] / "template" / "snarkjs-bls12-381.json"
    artifact = json.loads(path.read_text())
    key, signals, proof = load_artifacts(artifact["key"], artifact["proof"], artifact["public_signals"])

    def plain(point):
        if point is None:
            return ["0", "1", "0"]
        if isinstance(point[0], tuple):
            return [[str(i) for i in pair] for pair in (*point, (1, 0))]
        return [str(i) for i in (*point, 1)]

    plain_key = {
        **artifact["key"], "vk_alpha_1": plain(key.alpha), "vk_beta_2": plain(key.beta),
        "vk_gamma_2": plain(key.gamma), "vk_delta_2": plain(key.delta),
        "IC": [plain(point) for point in key.ic],
    }
    plain_proof = {"protocol": "groth16", "curve": "bls12381",
                   "pi_a": plain(proof.a), "pi_b": plain(proof.b), "pi_c": plain(proof.c)}
    return key, signals, proof, plain_key, plain_proof


class SnarkjsVerificationTests(unittest.TestCase):
    def test_artifact_formats(self):
        key, signals, proof, plain_key, plain_proof = imported()
        self.assertEqual(load_artifacts(plain_key, plain_proof, list(map(str, signals))), (key, signals, proof))
        self.assertTrue(verify_host(key, signals, proof))
        self.assertFalse(verify_host(key, (signals[0] + 1, signals[1]), proof))
        with self.assertRaisesRegex(ValueError, "over BLS12-381"):
            load_artifacts({**plain_key, "curve": "bn128"}, plain_proof, signals)

    def test_external_proof_complete_input(self):
        from shared.chain_gang import validate_at_heights

        key, signals, proof, _, _ = imported()
        valid = VerifierDescriptor(key, signals, "gamma")
        wrong_statement = VerifierDescriptor(key, signals[::-1], "gamma")
        for descriptor in (valid, wrong_statement):
            parent, spend = transactions(descriptor.build_lock()[0], descriptor.build_unlock(proof), 2)
            context = dict(spend_height=4, activation_height=3, utxo_heights=[3])
            if descriptor == valid:
                validate_at_heights(spend, [parent], **context)
            else:
                with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                    validate_at_heights(spend, [parent], **context)

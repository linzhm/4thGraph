"""Regression tests for the snarkjs-to-Rúnar coordinate and statement ABI."""

import json
import unittest

from groth16_script import BASE_FIELD, FIELD, g2, public_signals, runar_key, runar_proof


class Groth16EncodingTests(unittest.TestCase):
    def test_snarkjs_g2_is_real_first_and_only_vk_points_are_negated(self):
        point = [["11", "22"], ["33", "44"], ["1", "0"]]
        expected = {"x0": "11", "x1": "22", "y0": "33", "y1": "44"}
        self.assertEqual(g2(point), expected)
        negative = {**expected, "y0": str(BASE_FIELD - 33), "y1": str(BASE_FIELD - 44)}
        self.assertEqual(g2(point, negate=True), negative)
        g1 = ["1", "2", "1"]
        document = {"protocol": "groth16", "curve": "bn128"}
        key = {**document, "nPublic": 5, "IC": [g1] * 6, "vk_alpha_1": g1,
               "vk_beta_2": point, "vk_gamma_2": point, "vk_delta_2": point}
        self.assertEqual(runar_key(json.dumps(key))["betaNegG2"], negative)
        proof = {**document, "pi_a": g1, "pi_b": point, "pi_c": g1}
        self.assertEqual(runar_proof(json.dumps(proof))["B"], ["11", "22", "33", "44"])

    def test_public_signals_refuse_aliases_and_wrong_arity(self):
        self.assertEqual(public_signals('["0","1","19","1","2"]'), ("0", "1", "19", "1", "2"))
        for other in ([0] * 4, [0, 1, FIELD, 1, 2], [0, 1, "019", 1, 2], [0, 1, True, 1, 2]):
            with self.subTest(other=other), self.assertRaises(ValueError):
                public_signals(json.dumps(other))
        with self.assertRaisesRegex(ValueError, "affine G2"):
            g2([["0", "0"], ["0", "0"], ["0", "0"]])


if __name__ == "__main__":
    unittest.main()

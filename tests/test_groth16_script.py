"""Regression tests for the snarkjs-to-Rúnar coordinate and statement ABI."""

import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from unittest.mock import patch

from fourthgraph.bsv.script import asm
from fourthgraph.compiler.source import CompileError
from fourthgraph.replay import groth16_bn254 as replay
from fourthgraph.verification.groth16_bn254 import (
    BASE_FIELD, FIELD, ForthVerifier, ScriptVerifier, g2, public_signals, runar_key, runar_proof,
)


class Groth16EncodingTests(unittest.TestCase):
    def test_funded_replay_rejects_a_different_fixture_owner(self):
        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.json"
            owner = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            fixture.write_text(json.dumps({"owner_public_key": owner}), encoding="utf-8")
            args = ["replay", "--runar", directory, "--fixture", str(fixture),
                    "--output", str(Path(directory) / "replay.json")]
            stderr = StringIO()
            with (patch("sys.argv", args), redirect_stderr(stderr), patch.object(replay, "TestKeys") as keys,
                  patch.object(replay, "chain_metadata", side_effect=AssertionError("started regtest setup"))):
                keys.return_value.public = {"operator": bytes.fromhex(
                    "022bd7c7bf29f7ac8fdcf65a05cb6449e65fbeb5dca591acdc1249ca7ba1537488")}
                with self.assertRaises(SystemExit) as error:
                    replay.main()
            self.assertEqual(error.exception.code, 2)
            self.assertIn("fixture owner_public_key must match the regtest operator key", stderr.getvalue())

    def test_adapter_reads_each_instances_key_from_a_shared_working_directory(self):
        g1 = ["1", "2", "1"]
        g2_point = [["11", "22"], ["33", "44"], ["1", "0"]]
        key = {"protocol": "groth16", "curve": "bn128", "nPublic": 5, "IC": [g1] * 6,
               "vk_beta_2": g2_point, "vk_gamma_2": g2_point, "vk_delta_2": g2_point}
        readers = Barrier(2)

        def read_adapter_key(command, *, stdin):
            path = Path(json.loads(stdin)["VK"])
            readers.wait(timeout=5)
            alpha = json.loads(path.read_bytes())["alphaG1"]
            return json.dumps(bytes([int(alpha["x"])]).hex())

        with TemporaryDirectory() as directory, patch("fourthgraph.verification.groth16_bn254.checked", side_effect=read_adapter_key):
            verifiers = [ScriptVerifier("adapter", json.dumps({**key, "vk_alpha_1": [x, "2", "1"]}).encode(),
                                        directory) for x in ("1", "3")]
            with ThreadPoolExecutor(max_workers=2) as pool:
                calls = [pool.submit(verifier.emit, ("0",) * 5) for verifier in verifiers]
                self.assertEqual([call.result() for call in calls], [b"\x01", b"\x03"])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_bn254_forth_links_the_same_predicate_and_requires_authorization(self):
        g1 = ["1", "2", "1"]
        g2_point = [["11", "22"], ["33", "44"], ["1", "0"]]
        key = json.dumps({"protocol": "groth16", "curve": "bn128", "nPublic": 5, "IC": [g1] * 6,
                          "vk_alpha_1": g1, "vk_beta_2": g2_point, "vk_gamma_2": g2_point,
                          "vk_delta_2": g2_point}).encode()
        source = Path(__file__).resolve().parents[1] / "projects/groth16-bn254/verifier.fth"
        owner = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        signals = ("0",) * 5
        with TemporaryDirectory() as directory, patch.object(ScriptVerifier, "emit",
                                                            return_value=asm("OP_0 OP_CHECKSIGVERIFY OP_1")):
            bytecode = ScriptVerifier("adapter", key, directory).compile(signals, owner)
            verifier = ForthVerifier("adapter", key, directory, source.read_bytes(), source_path=source)
            self.assertEqual(verifier.compile(signals, owner), bytecode)
            artifact = verifier.artifact(signals, owner, bytecode)
            self.assertEqual(artifact["forth_entry"], "verify-bn254-proof")
            self.assertEqual([library["name"] for library in artifact["libraries"]], ["forth/statement.fth"])
            source_without_owner = source.read_bytes().replace(b"    bn254-owner-guard\n", b"")
            with self.assertRaises(CompileError):
                ForthVerifier("adapter", key, directory, source_without_owner, source_path=source)

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

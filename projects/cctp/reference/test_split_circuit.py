import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from circom_fixture_prover import CompiledProver
from shared.transaction import preimage_all
from statement import TRANSFER_DOMAIN, public_inputs
from verifier import verify_host
import test_statement


@unittest.skipUnless(shutil.which("circom") and shutil.which("node"), "requires Circom and Node.js")
class SplitCircuitTests(unittest.TestCase):
    def test_python_statement_matches_circuit(self):
        project = Path(__file__).resolve().parents[1]
        fixture = test_statement.StatementTests()
        fixture.setUp()
        statement = fixture.statement()
        spent = fixture.parent.outputs[0]
        preimage = preimage_all(fixture.tx, 0, spent.value, spent.script)
        with TemporaryDirectory(prefix=".split-circuit-", dir=project) as directory:
            build = Path(directory)
            subprocess.run(
                ["circom", str(project / "circuits/split_commitment.circom"),
                 "--prime", "bls12381", "--r1cs", "--wasm", "-o", str(build)],
                check=True, capture_output=True, text=True,
            )
            generated = build / "split_commitment_js"
            witness_input = build / "input.json"
            command = ["node", str(generated / "generate_witness.js"),
                       str(generated / "split_commitment.wasm"), str(witness_input),
                       str(build / "witness.wtns")]

            def witness(raw, digest, transaction_preimage=preimage):
                payload = raw[len(TRANSFER_DOMAIN):]
                witness_input.write_text(json.dumps({
                    "prefix": list(payload[:64]),
                    "preimage": list(transaction_preimage),
                    "inputSlots": [list(payload[98:110])],
                    "outputSlots": [list(payload[112:124]), list(payload[124:136])],
                    "digestHigh": str(digest[0]),
                    "digestLow": str(digest[1]),
                }))
                return subprocess.run(command, capture_output=True, text=True)

            expected = public_inputs(statement)
            valid = witness(statement, expected)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            prover = CompiledProver.load(build / "split_commitment.r1cs")
            signals, proof = prover.prove(build / "witness.wtns")
            self.assertEqual(signals, expected)
            self.assertTrue(verify_host(prover.key, signals, proof))
            self.assertFalse(verify_host(prover.key, signals[::-1], proof))
            altered_prefix = bytearray(statement)
            altered_prefix[len(TRANSFER_DOMAIN)] ^= 1
            self.assertIn("Assert Failed", witness(altered_prefix, public_inputs(statement)).stderr)
            changed_preimage = bytearray(preimage)
            changed_preimage[-9] ^= 1
            self.assertIn("Assert Failed", witness(statement, expected, changed_preimage).stderr)
            inflation = statement[:-8] + (385).to_bytes(8, "little")
            self.assertIn("Assert Failed", witness(inflation, public_inputs(inflation)).stderr)

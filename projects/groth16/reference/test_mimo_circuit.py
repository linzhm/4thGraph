"""Compile configurable MIMO capacities and run actual Circom witnesses."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from mimo_witness import MimoInput, witness

CIRCUITS = Path(__file__).resolve().parents[1] / "circuits"


def sample(count_in, count_out, capacity):
    total = max(128, count_in, count_out)
    inputs = [MimoInput(i.to_bytes(36, "big"), 1 if i else total - count_in + 1)
              for i in reversed(range(count_in))]
    outputs = [total - count_out + 1] + [1] * (count_out - 1)
    return witness(inputs, outputs, *capacity)


@unittest.skipUnless(shutil.which("circom") and shutil.which("node"), "requires Circom and Node.js")
class MimoCircuitTests(unittest.TestCase):
    def check_capacity(self, capacity, shapes, *, prove_split=False):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            shutil.copyfile(CIRCUITS / "mimo_relation.circom", project / "mimo_relation.circom")
            main = project / "transfer.circom"
            main.write_text(
                'pragma circom 2.2.3;\ninclude "mimo_relation.circom";\n'
                f'component main {{public [inputTotal, outputTotal]}} = MimoRelation({capacity[0]}, {capacity[1]});\n'
            )
            process = subprocess.run(
                ["circom", str(main), "--r1cs", "--wasm", "--prime", "bls12381", "-o", directory],
                cwd=directory, capture_output=True, text=True,
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            js = project / "transfer_js"
            data = project / "input.json"

            def check(inputs, valid):
                data.write_text(json.dumps(inputs))
                output = project / "witness.wtns"
                output.unlink(missing_ok=True)
                step = subprocess.run(
                    ["node", str(js / "generate_witness.js"), str(js / "transfer.wasm"), str(data), str(output)],
                    capture_output=True, text=True,
                )
                self.assertEqual(step.returncode == 0, valid, step.stderr)
                self.assertEqual(output.exists(), valid)
                if not valid:
                    self.assertIn("Assert Failed", step.stderr)

            if prove_split:
                from circom_fixture_prover import CompiledProver
                from descriptor import VerifierDescriptor
                from shared.evaluate import evaluate
                from verifier import verify_host

                split = witness([MimoInput(bytes(36), 1024)], [640, 384], *capacity)
                check(split, True)
                prover = CompiledProver.load(project / "transfer.r1cs")
                public, proof = prover.prove(project / "witness.wtns")
                self.assertEqual(public, (1024, 1024))
                self.assertTrue(verify_host(prover.key, public, proof))
                descriptor = VerifierDescriptor(prover.key, public, "gamma")
                signature_script = descriptor.build_unlock(proof)
                self.assertEqual(evaluate(signature_script + descriptor.build_lock()[0]), ([b"\x01"], []))
                self.assertFalse(verify_host(prover.key, (1024, 1025), proof))
                # Supply invalid output witness directly, bypassing the host amount validator.
                split["outputAmount"][1] = "385"
                split["outputTotal"] = "1025"
                check(split, False)

            for count_in, count_out in shapes:
                with self.subTest(shape=(count_in, count_out)):
                    check(sample(count_in, count_out, capacity), True)
            valid = sample(*capacity, capacity)
            duplicate = deepcopy(valid)
            duplicate["inputLow"][1] = duplicate["inputLow"][0]
            check(duplicate, False)
            unsorted = deepcopy(valid)
            unsorted["inputLow"][:2] = reversed(unsorted["inputLow"][:2])
            check(unsorted, False)
            inflated = deepcopy(valid)
            inflated["outputAmount"][-1] = "2"
            check(inflated, False)
            oversized = deepcopy(valid)
            oversized["inputAmount"][0] = str(2**64)
            check(oversized, False)

    def test_16_slots_each(self):
        self.check_capacity((16, 16), ((2, 1), (1, 2), (4, 4), (16, 16)), prove_split=True)

    def test_32_slots_each(self):
        self.check_capacity((32, 32), ((32, 32), (32, 1), (1, 32)))

    def test_asymmetric_capacity(self):
        self.check_capacity((16, 32), ((16, 32),))

    def test_64_slots_each(self):
        self.check_capacity((64, 64), ((64, 64), (4, 64), (64, 4)))

    def test_256_slots_each(self):
        self.check_capacity((256, 256), ((256, 256),))

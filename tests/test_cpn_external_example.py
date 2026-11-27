"""The documented external-witness example plans and checks its provenance."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "projects" / "proof-counter"


class ExternalWitnessExampleTests(unittest.TestCase):
    def test_public_and_private_examples(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("cpn-external-witness.json", "cpn-external-witness-private.json",
                         "cpn-external-words.fth", "counter.fth"):
                shutil.copyfile(EXAMPLE / name, directory / name)
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src") + os.pathsep + str(ROOT))

            def run(*arguments):
                return subprocess.run([sys.executable, "-m", "fourthgraph.workflow.protocol", "cpn", *arguments],
                                      cwd=ROOT, env=env, text=True, capture_output=True, check=False)

            keys = run("test-keys")
            self.assertEqual(keys.returncode, 0, keys.stderr)
            (directory / "keys.json").write_text(keys.stdout)
            for visibility in ("public", "private"):
                with self.subTest(visibility=visibility):
                    model = directory / ("cpn-external-witness.json" if visibility == "public" else
                                         "cpn-external-witness-private.json")
                    workflow = directory / (visibility + "-workflow.fth")
                    report_file = directory / (visibility + "-report.json")
                    result = run("tune-model", str(model), "--source", str(directory / "cpn-external-words.fth"),
                                 "--output", str(workflow), "--keys", str(directory / "keys.json"),
                                 "--current", "19", "--optimizations", "stack")
                    report_file.write_text(result.stdout)
                    report = json.loads(result.stdout)
                    candidates = report.get("schedule_explanation", report)["candidates"]
                    if visibility == "public":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(candidates["fused/r1cs~stack"]["eligible"])
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        for backend in ("script", "r1cs"):
                            self.assertIn("private_witness_disclosure", [item["code"] for item in
                                candidates[f"fused/{backend}~stack"]["exclusions"]])
                        self.assertIn("missing_setup", [item["code"] for item in
                            candidates["fused/groth16-bls12-381~stack"]["exclusions"]])
                    checked = run("verify-model", str(model), "--source", str(directory / "cpn-external-words.fth"),
                                  "--workflow", str(workflow), "--report", str(report_file))
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                    provenance = json.loads(checked.stdout)
                    self.assertEqual(provenance["scope"], "logical-model-lowering-provenance")
                    self.assertTrue(provenance["report_checked"])
                    self.assertIn("proof verification", provenance["not_checked"])


if __name__ == "__main__":
    unittest.main()

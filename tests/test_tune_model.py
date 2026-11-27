"""Exercise logical CPN exploration and reproducible selection."""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from fourthgraph.replay.workflow import TestKeys

ROOT = Path(__file__).resolve().parents[1]


class TuneModelTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        for name in ("cpn-linear.json", "cpn-words.fth", "counter.fth"):
            shutil.copyfile(ROOT / "projects/proof-counter" / name, self.directory / name)
        self.keys = self.directory / "keys.json"
        self.keys.write_text(json.dumps({role: key.hex() for role, key in TestKeys().public.items()}))
        self.output = self.directory / "generated.fth"

    def run_command(self, *arguments):
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src") + os.pathsep + str(ROOT))
        return subprocess.run([sys.executable, "-m", "fourthgraph.workflow.protocol", "cpn", *arguments],
                              text=True, capture_output=True, cwd=self.directory, env=env)

    def explore(self, *options):
        return self.run_command("tune-model", str(self.directory / "cpn-linear.json"), "--source",
                                str(self.directory / "cpn-words.fth"), "--output", str(self.output),
                                "--keys", str(self.keys), "--current", "19", "--optimizations", "stack", *options)

    def test_model_explores_and_selected_candidate_rebuilds(self):
        run = self.explore()
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)["schedule_explanation"]
        model_digest = sha256((self.directory / "cpn-linear.json").read_bytes()).hexdigest()
        self.assertIn("logical-cpn-sha256 " + model_digest, self.output.read_text())
        self.assertEqual(report["source_sha256"], sha256(self.output.read_bytes()).hexdigest())
        self.assertTrue(report["candidates"]["fused/script~stack"]["eligible"])
        report_file = self.directory / "report.json"
        report_file.write_text(run.stdout)
        rebuilt = self.run_command("plan", str(self.output), "--select-candidate", str(report_file),
                                   "fused/script~stack", "--cpn-plan")
        self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
        self.output.write_text(self.output.read_text() + "\\ modified\n")
        changed = self.run_command("plan", str(self.output), "--select-candidate", str(report_file),
                                   "fused/script~stack", "--cpn-plan")
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("source digest changed", changed.stderr)

    def test_existing_output_is_not_overwritten_and_bad_models_fail(self):
        self.output.write_text("user data\n")
        run = self.explore()
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(self.output.read_text(), "user data\n")
        self.output.unlink()
        model = self.directory / "cpn-linear.json"
        document = json.loads(model.read_text())
        document["transitions"][0]["metadata"]["constraints"] = ["unimplemented"]
        model.write_text(json.dumps(document))
        run = self.explore()
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_no_eligible_candidate_produces_exclusion_report(self):
        run = self.explore("--max-lock-bytes", "1")
        self.assertNotEqual(run.returncode, 0)
        report = json.loads(run.stdout)
        self.assertIsNone(report["selected"])
        self.assertTrue(self.output.exists())
        self.assertTrue(any(item["code"] == "lock_byte_budget" for row in report["candidates"].values()
                            for item in row.get("exclusions", [])))

    def test_layout_requirements_change_model_candidates(self):
        model = self.directory / "cpn-linear.json"
        document = json.loads(model.read_text())
        document["transitions"][0]["metadata"]["atomic_with"] = ["decide"]
        model.write_text(json.dumps(document))
        result = self.explore()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)["schedule_explanation"]["candidates"]
        self.assertTrue(rows["fused/script~stack"]["eligible"])
        self.assertIn("atomicity_required", [item["code"] for item in rows["serial/script~stack"]["exclusions"]])
        self.output.unlink()
        document["transitions"][1]["metadata"]["independent_submit"] = True
        model.write_text(json.dumps(document))
        conflict = self.explore()
        self.assertNotEqual(conflict.returncode, 0)
        self.assertIsNone(json.loads(conflict.stdout)["selected"])

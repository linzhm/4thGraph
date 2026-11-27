"""Regression checks for the two Plonky3 SHA-256 FRI Script profiles."""

import json
from pathlib import Path
import unittest

from fourthgraph.verification.stark.cli import build_artifacts, check, controls, fixture
from fourthgraph.verification.stark.proof import BABYBEAR, GOLDILOCKS

PROJECTS = Path(__file__).resolve().parents[1] / "projects"


class StarkVerifierTests(unittest.TestCase):
    def test_rebuild_and_verify_exported_proofs(self):
        for name, profile in (("plonky3", BABYBEAR), ("goldilocks", GOLDILOCKS)):
            with self.subTest(profile=profile.name):
                project = PROJECTS / f"{name}-stark-verifier"
                source = project / "verifier.fth"
                cases = fixture(project)
                build = build_artifacts(profile, source, *cases["valid"])

                versions = project / "versions"
                current = json.loads((versions / "index.json").read_text())["current"]
                release = versions / f"v{current}"
                previous = versions / "v0.1.0"
                self.assertEqual(build.forth, (release / "verifier.fth").read_text(encoding="utf-8"))
                self.assertEqual(build.lock, (release / "lock.bin").read_bytes())
                self.assertLess(len(build.lock), (previous / "lock.bin").stat().st_size)
                self.assertEqual(build.unlock, (previous / "unlock.bin").read_bytes())

                report = check(profile, source, cases, build.lock, build.unlock, controls(profile, cases))
                self.assertTrue(report["verdicts"]["valid"])
                self.assertTrue(report["verdicts"]["wrapping_statement"])
                self.assertFalse(report["verdicts"]["wrong_air_same_statement"])

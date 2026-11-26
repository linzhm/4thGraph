from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from comparison_report import SCHEMA_VERSION, read_report
from msm_experiment import SOURCE, compare


class ComparisonReportTests(unittest.TestCase):
    def test_compare_can_reuse_its_output_as_a_reference(self):
        options = dict(
            source=SOURCE, workflow="explicit", candidate=["joint-2-affine-g"], budget=1, full_budget=1,
            vectors=12, samples=1, matrix=False,
        )
        previous, _ = compare(SimpleNamespace(**options, reference=None))
        self.assertEqual(previous["schema_version"], SCHEMA_VERSION)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "comparison.json"
            contents = json.dumps(previous).encode()
            path.write_bytes(contents)
            current, _ = compare(SimpleNamespace(**options, reference=path))
            self.assertEqual(current["reference_sha256"], sha256(contents).hexdigest())
            self.assertEqual(current["candidates"], previous["candidates"])

    def test_invalid_reports_identify_the_version_or_candidate(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "reference.json"
            for report, error in (
                ({"layouts": {}}, "schema_version 2"),
                ({"candidates": {}}, "schema_version 2"),
                ({"schema_version": 99, "candidates": {}}, "schema_version 2"),
                ({"schema_version": 2, "layouts": {}}, "candidates"),
                ({"schema_version": 2, "candidates": {"split-4": {"status": "verified", "measured": 12}}},
                 "split-4.*measured"),
            ):
                with self.subTest(report=report):
                    path.write_text(json.dumps(report))
                    with self.assertRaisesRegex(ValueError, rf"reference\.json: .*{error}"):
                        read_report(path)

    def test_a_candidate_skipped_by_the_reference_is_still_new(self):
        name = "split-4-affine-g"
        options = dict(
            source=SOURCE, workflow="explicit", candidate=[name], budget=1, full_budget=1,
            vectors=12, samples=1, matrix=False,
        )
        with TemporaryDirectory() as directory, patch(
            "msm_experiment.local_build", return_value=(None, {"status": "local-verified"})
        ), patch("msm_experiment.shortlist", return_value=()):
            path = Path(directory) / "reference.json"
            for row, novel in (
                ({"status": "not-tested", "reason": "local candidate budget exhausted"}, True),
                ({"status": "local-only", "estimated": {"lock_bytes": 41538}}, False),
            ):
                with self.subTest(status=row["status"]):
                    path.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "candidates": {name: row}}))
                    report, _ = compare(SimpleNamespace(**options, reference=path))
                    self.assertEqual(report["timing"]["first_novel_locally_verified_seconds"] is not None, novel)


if __name__ == "__main__":
    unittest.main()

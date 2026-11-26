from hashlib import sha256
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from comparison_report import SCHEMA_VERSION, read_report
from msm_experiment import SOURCE, compare, guided_candidates, main
from msm_compiler import R1MSMCompiler


class ComparisonReportTests(unittest.TestCase):
    def test_guided_search_follows_the_frozen_construction(self):
        compiler = R1MSMCompiler()
        candidates, proposal, scans = guided_candidates(compiler, 2)
        self.assertEqual(candidates[:2], ("v0.6.0", "split-5x4-affine-g-ifdup"))
        self.assertEqual(proposal["id"], "affine-g-ifdup")
        self.assertIn(proposal["try"], scans)
        self.assertEqual(len(set(candidates)), len(candidates))

        _, proposal, _ = guided_candidates(compiler, 1)
        self.assertIsNone(proposal)

    def test_compare_builds_the_frozen_control_and_guided_rewrite_within_budget(self):
        options = dict(source=SOURCE, workflow="guided", candidate=None, full_budget=1,
                       vectors=12, samples=1, matrix=False, reference=None)
        for budget in (1, 2):
            with self.subTest(budget=budget), patch(
                "msm_experiment.local_build", return_value=(None, {"status": "local-verified"})
            ) as build, patch("msm_experiment.shortlist", return_value=()):
                report, _ = compare(SimpleNamespace(**options, budget=budget))
                checked = [name for name, row in report["candidates"].items() if row["status"] == "local-verified"]
                self.assertEqual(checked, ["v0.6.0", "split-5x4-affine-g-ifdup"][:budget])
                self.assertEqual(build.call_count, budget - 1)
                self.assertEqual(report["source_verification"], {"status": "unverified", "verified_candidates": []})
                self.assertEqual(report["candidates"]["v0.6.0"]["origin"], "frozen")
                if budget == 2:
                    self.assertEqual(build.call_args.args[1].strategy.name, "split-5x4-affine-g-ifdup")
                    row = report["candidates"]["split-5x4-affine-g-ifdup"]
                    self.assertEqual(row["origin"], "source")
                    self.assertEqual(row["build_source"]["source_sha256"], report["source_sha256"])

    def test_compare_cli_requires_replay_of_explicit_source(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "custom.fth"
            output = source.with_suffix(".json")
            arguments = ["msm_experiment", "compare", "--output", str(output)]
            for explicit, candidates, expected in ((False, [], 0), (True, [], 1), (True, ["split-5x4"], 0)):
                status = "verified" if candidates else "unverified"
                report = {"selected": {"lock_bytes": "v0.6.0"}, "source_verification": {
                    "status": status, "verified_candidates": candidates,
                }}
                argv = arguments + (["--source", str(source)] if explicit else [])
                with self.subTest(explicit=explicit, candidates=candidates), patch.object(sys, "argv", argv), patch(
                    "msm_experiment.compare", return_value=(report, {})
                ) as replay:
                    self.assertEqual(main(), expected)
                    self.assertEqual(replay.call_args.args[0].source, source if explicit else SOURCE)
                    self.assertEqual(json.loads(output.read_text()), report)

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

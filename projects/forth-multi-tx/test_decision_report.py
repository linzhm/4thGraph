"""Exercise decision evidence at the CLI and with an offline wire fixture."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from compiler import parse
from decision_report import decision_report, markdown
from protocol import artifact_digest, compile_decision
from replay import EXAMPLE, TASK_ID, TestKeys
from shared.transaction import Input, Transaction


def tx_record(tx, passed=True):
    return {
        "txid": tx.txid(), "raw": tx.serialize().hex(), "transaction_version": tx.version,
        "previous": [f"{item.txid[::-1].hex()}:{item.vout}" for item in tx.inputs],
        "bytes": len(tx.serialize()),
        "bsv_node": {"input_scripts": [passed] * len(tx.inputs), "mempool": passed, "mined": passed},
        "chain_gang": {"transaction": passed},
    }


class DecisionReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = TestKeys()
        source = EXAMPLE.read_bytes()
        constrained_source = source + b"\nindependent-submit a\n"
        options = dict(mode="auto", target="both", optimization="stack", join_witness="shared")
        contracts, artifacts, original = compile_decision(parse(source.decode()), cls.keys.public, TASK_ID,
                                                          source_bytes=source, **options)
        constrained, extra_artifacts, constrained_decision = compile_decision(
            parse(constrained_source.decode()), cls.keys.public, TASK_ID, source_bytes=constrained_source, **options,
        )
        root = contracts["fused"].root
        bootstrap = Transaction((Input(bytes(32), 0),), (root,) * 6)
        cls.fixture = {
            "project": "4thGraph", "schema_version": 2, "compiler_version": artifacts["fused"]["compiler_version"],
            "bootstrap_raw": bootstrap.serialize().hex(), "target": "both", "topology": "parallel",
            "regtest_profile": "default", "sample_count": 1, "bsv_node_version": 101020300,
            "chain_gang": {"commit": "test"}, "optimization": "stack", "join_witness": "shared",
            "chronicle_activation_height": 2,
            "source": source.decode(), "constrained_source": constrained_source.decode(),
            "decisions": {"original": original, "constrained": constrained_decision},
            "plans": {**artifacts, "constrained": extra_artifacts["split"]}, "cases": {},
        }
        for plan_id, contract in (*contracts.items(), ("constrained", constrained["split"])):
            for route, xs in (("settle", {"x": 10, "y": 5}), ("review", {"x": 0, "y": 0})):
                artifact = cls.fixture["plans"][plan_id]
                deploy = Transaction((Input(bootstrap.txid_wire(), len(cls.fixture["cases"])),), (contract.root,))
                done = {"deploy": deploy}
                for step in contract.plan.templates:
                    draft = contract.prepare(step.name, done, xs)
                    done[step.name] = draft.seal(cls.keys.sign)
                steps = {name: tx_record(tx) for name, tx in done.items()}
                sizes = [row["bytes"] for row in steps.values()]
                cost = artifact["estimated_cost"]
                cls.fixture["cases"][f"{plan_id}_{route}"] = {
                    "route": route, "scenario": "constrained" if plan_id == "constrained" else "original",
                    "candidate": contract.plan.mode, "artifact_sha256": artifact["artifact_sha256"],
                    "source_sha256": artifact["source_sha256"], "data": xs, "steps": steps, "controls": {},
                    "metrics": {
                        "whole_path_bytes": sum(sizes), "max_transaction_bytes": max(sizes),
                        "max_single_transaction_bsv_verify_rpc_median_ms": 0.8,
                        "max_single_transaction_chain_gang_median_ms": 0.2,
                        "peak_stack": dict(main_payload_bytes=3, alt_payload_bytes=2, combined_payload_bytes=4),
                        "dependency_depth_including_deploy": cost["dependency_depth_including_deploy"],
                        "intermediate_utxos": 4 if contract.plan.mode == "split" else 0,
                    },
                }

    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "replay.json"
        self.replay = deepcopy(self.fixture)

    def report(self, baselines=()):
        self.path.write_text(json.dumps(self.replay), encoding="utf-8")
        return decision_report(self.path, baselines)

    def test_report_is_reproducible_and_distinguishes_both_routes_and_static_status(self):
        first = self.report()
        self.assertEqual(first, self.report())
        self.assertEqual(markdown(first), markdown(self.report()))
        scenarios = first["scenarios"]
        self.assertEqual(scenarios["original"]["selected"], "fused")
        self.assertEqual(scenarios["constrained"]["selected"], "split")
        excluded = scenarios["constrained"]["candidates"]["fused"]
        reason, = excluded["exclusions"]
        self.assertEqual((reason["code"], reason["step"]), ("independent_submit", "a"))
        self.assertEqual(self.replay["constrained_source"].splitlines()[reason["line"] - 1], "independent-submit a")
        self.assertEqual(excluded["static_status"], "excluded")
        self.assertEqual(excluded["replay"]["settle"]["status"], "not_run")
        self.assertEqual(scenarios["original"]["candidates"]["split"]["words"]["route"]["word"], "decide")
        self.assertEqual(scenarios["original"]["candidates"]["split"]["replay"]["review"]["status"], "passed")

    def test_mismatched_digest_route_and_parent_raise(self):
        for field, value in (("artifact_sha256", "0" * 64), ("route", "review")):
            with self.subTest(field=field):
                self.replay = deepcopy(self.fixture)
                self.replay["cases"]["split_settle"][field] = value
                with self.assertRaisesRegex(ValueError, "split_settle"):
                    self.report()
        self.replay = deepcopy(self.fixture)
        review_join = self.replay["cases"]["split_review"]["steps"]["route"]
        self.replay["cases"]["split_settle"]["steps"]["route"] = review_join
        with self.assertRaisesRegex(ValueError, "route does not spend its bound parents"):
            self.report()

    def test_missing_evidence_and_failing_verdict_do_not_change_static_eligibility(self):
        del self.replay["cases"]["fused_review"]
        self.replay["cases"]["fused_settle"]["steps"]["fused"]["chain_gang"]["transaction"] = False
        candidate = self.report()["scenarios"]["original"]["candidates"]["fused"]
        self.assertEqual(candidate["static_status"], "eligible")
        self.assertEqual(candidate["replay"]["review"]["status"], "not_run")
        self.assertEqual(candidate["replay"]["settle"]["status"], "failed")

    def test_report_rejects_a_selection_that_disagrees_with_rank(self):
        self.replay["decisions"]["original"]["selected"] = "split"
        with self.assertRaisesRegex(ValueError, "selection does not match the static ranking"):
            self.report()

    def test_historical_split_review_retains_constrained_source(self):
        archive = deepcopy(self.replay)
        archive["schema_version"] = 1
        archive["compiler_version"] = "0.1.0"
        archive["cases"] = {name: archive["cases"][name] for name in ("fused_settle", "fused_review", "split_settle",
                                                                      "constrained_review")}
        archive["cases"]["split_review"] = archive["cases"].pop("constrained_review")
        path = self.directory / "historical.json"
        path.write_text(json.dumps(archive), encoding="utf-8")
        old, = self.report([path])["historical_baseline"]
        row = old["cases"]["split_review"]
        self.assertEqual((row["scenario"], row["route"], row["status"]), ("constrained", "review", "passed"))
        self.assertEqual(row["source_sha256"], self.fixture["plans"]["constrained"]["source_sha256"])

    def test_cli_candidate_has_same_digest_as_plain_build(self):
        keys = self.directory / "keys.json"
        keys.write_text(json.dumps({name: value.hex() for name, value in self.keys.public.items()}))
        command = [sys.executable, str(EXAMPLE.with_name("protocol.py")), str(EXAMPLE), "--target", "both",
                   "--optimize", "stack", "--join-witness", "shared", "--keys", str(keys), "--task-id", TASK_ID.hex()]
        explained = json.loads(subprocess.check_output([*command, "--explain"]))
        plain = json.loads(subprocess.check_output([*command, "--mode", "split"]))
        candidate = explained["schedule_explanation"]["candidates"]["split"]
        self.assertEqual(candidate["artifact_sha256"], plain["artifact_sha256"])
        self.assertEqual(candidate["artifact_sha256"], self.fixture["plans"]["split"]["artifact_sha256"])
        self.assertEqual(explained["artifact_sha256"], artifact_digest(explained))


if __name__ == "__main__":
    unittest.main()

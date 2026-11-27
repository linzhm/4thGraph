"""Regression cases for joint proof and transaction planning."""

from pathlib import Path
from tempfile import TemporaryDirectory
from hashlib import sha256
import json
import re
import unittest

from fourthgraph.bsv.transaction import Output
from fourthgraph.compiler.source import CompileError, SourceCompiler
from fourthgraph.replay.workflow import TestKeys
from fourthgraph.verification.circuit_backend import emit_stage_circuit
from fourthgraph.verification.lineage import lineage_statement
from fourthgraph.workflow.cpn_workbench import carried_state, export_workbench
from fourthgraph.workflow.proof_planner import compile_evidence_plans, evidence_path, rebuild_candidate
from fourthgraph.workflow.workflow_contract import state_fields

SOURCE = Path(__file__).resolve().parents[1] / "projects/proof-counter/workflow.fth"


class WorkflowEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.keys = TestKeys().public
        self.options = dict(mode="auto", target="both", optimization="stack", objective="path-bytes",
                            available_authorizers=None, sighash_family="bip143")

    def compile(self, directives, **kwargs):
        source = SourceCompiler(SOURCE.read_text() + "\n" + directives, source_path=SOURCE)
        return source, compile_evidence_plans(source, self.keys, 19, self.directory, **self.options, **kwargs)

    def test_atomic_policy_and_exact_rebuild(self):
        source, (contract, artifact) = self.compile("atomic: advance decide ;")
        report = artifact["schedule_explanation"]
        self.assertIsNotNone(contract)
        self.assertEqual(report["selected"], "fused/script")
        self.assertIn("atomicity_required", [reason["code"] for reason in
                                            report["candidates"]["serial/script"]["exclusions"]])
        self.assertIn("missing_setup", [reason["code"] for reason in
                                       report["candidates"]["fused/groth16-bls12-381"]["exclusions"]])
        round_trip = json.loads(json.dumps(artifact))
        _, rebuilt = rebuild_candidate(source, round_trip, "atomic/script", self.directory, None)
        self.assertEqual(rebuilt["plan_sha256"], report["candidates"]["atomic/script"]["plan_sha256"])
        round_trip["schedule_explanation"]["imports"]["counter.fth"] = "different"
        with self.assertRaisesRegex(CompileError, "import digests changed"):
            rebuild_candidate(source, round_trip, "atomic/script", self.directory, None)

    def test_private_stage_fails_closed_with_no_setup(self):
        path = SOURCE.with_name("workflow-private.fth")
        source = SourceCompiler(path.read_text(), source_path=path)
        contract, report = compile_evidence_plans(source, self.keys, 19, self.directory, **self.options)
        self.assertIsNone(contract)
        self.assertIsNone(report["selected"])
        for backend in ("script", "r1cs"):
            codes = [row["code"] for row in report["candidates"][f"fused/{backend}"]["exclusions"]]
            self.assertIn("private_witness_disclosure", codes)
        circuit, public = emit_stage_circuit(source.workflow().stages[-1])
        self.assertEqual(public, ("route", "state", "bindLo", "bindHi"))
        self.assertIn(b"signal input witness0", circuit)
        self.assertNotIn(b"public [state, bindLo, bindHi, witness0]", circuit)

    def test_profile_tuning_pins_the_exact_variant_and_compares_one_source(self):
        source, (_, artifact) = self.compile("", optimizations=("baseline", "safe", "stack"))
        report = artifact["schedule_explanation"]
        candidates = report["candidates"]
        self.assertEqual(report["ranked_candidates"][0], report["selected"])
        self.assertEqual(artifact["optimization"], candidates[report["selected"]]["optimization"])
        for profile in ("baseline", "safe", "stack"):
            name = f"fused/script~{profile}"
            self.assertTrue(candidates[name]["eligible"])
            self.assertEqual(candidates[name]["optimization"], profile)
            _, rebuilt = rebuild_candidate(source, json.loads(json.dumps(artifact)), name, self.directory, None)
            self.assertEqual(rebuilt["optimization"], profile)
            self.assertEqual(rebuilt["plan_sha256"], candidates[name]["plan_sha256"])
        with self.assertRaisesRegex(CompileError, "distinct compiler optimizations"):
            self.compile("", optimizations=("stack", "stack"))

    def test_recursive_edge_resolves_wire_slots_and_preserves_issuance(self):
        source = """
: tx-edge ( transaction -- outpoint outpoint )
    dup #0 tx-input-prevout swap #1 tx-output-outpoint ;
recursive: lineage tx-edge ;
"""
        statement = lineage_statement(SourceCompiler(source), "lineage")
        self.assertEqual((statement["input_slot"], statement["output_slot"]), (0, 1))
        self.assertIn("same_issuance", statement["step"])
        self.assertIn("valid_predecessor_proof", statement["step"])
        reverse = source.replace("tx-output-outpoint ;", "tx-output-outpoint swap ;")
        with self.assertRaisesRegex(CompileError, "consumed outpoint before"):
            lineage_statement(SourceCompiler(reverse), "lineage")
        _, (contract, report) = self.compile(source)
        self.assertIsNone(contract)
        self.assertEqual(report["recursive_statements"], [statement])
        self.assertIn("recursive_backend_unavailable", [row["code"] for row in
                      report["candidates"]["fused/script"]["exclusions"]])

    def test_workbench_embeds_original_report_and_canonical_plan_as_data(self):
        _, (_, artifact) = self.compile("")
        report, output = self.directory / "report.json", self.directory / "workbench.html"
        report.write_text(json.dumps(artifact))
        title = "</script><tag>"
        export_workbench(report, [], output=output, title=title)
        html = output.read_text()
        self.assertNotIn(title, html)
        (embedded,) = re.findall(r'<script id="workbench-data" type="application/json">(.*?)</script>', html)
        payload = json.loads(embedded)
        self.assertEqual(payload["title"], title)
        self.assertEqual(payload["report"], json.loads(report.read_bytes()))
        plan = payload["packages"][payload["selected"]]["plan"]
        self.assertEqual(sha256(plan.encode()).hexdigest(), artifact["plan_sha256"])
        with self.assertRaisesRegex(ValueError, "unknown candidate"):
            export_workbench(report, [], output=output, title=title, selected="unreported")

    def test_workbench_decodes_only_the_declared_state_carrier(self):
        root = bytes(range(32))
        state = state_fields(root, 20)
        build = {"state_output": {"satoshis": 100, "script_suffix_hex": "51"},
                 "receipt": {"satoshis": 0, "script_prefix_hex": "006a"}}
        expected = {"state_u32": 20, "root_txid": root[::-1].hex()}
        self.assertEqual(carried_state(Output(100, state + b"\x51"), "state", "advance", build), expected)
        self.assertEqual(carried_state(Output(0, b"\x00\x6a" + state), "receipt", "decide", build), expected)
        self.assertEqual(carried_state(Output(100, state + b"\x52"), "state", "advance", build), {})

    def test_composition_checks_statement_flow_and_refuses_unlinked_paths(self):
        path = {
            "stage": "decide", "terminal": "snark",
            "nodes": {
                "snark": {"backend": "groth16-bls12-381", "proves": "decide", "requires": {"stark": "edge"}},
                "stark": {"backend": "winterfell-sha256", "proves": "edge", "requires": {}},
            },
        }
        config = self.directory / "catalog.json"
        config.write_text(json.dumps({"evidence_paths": {"wrap": path}}))
        _, (_, artifact) = self.compile("", catalog=config)
        row = artifact["schedule_explanation"]["candidates"]["evidence/wrap"]
        self.assertEqual([item["id"] for item in row["evidence_graph"]["nodes"]], ["stark", "snark"])
        self.assertFalse(row["eligible"])
        path["nodes"]["stark"]["requires"] = {"snark": "decide"}
        with self.assertRaisesRegex(ValueError, "cycle"):
            evidence_path("wrap", path, {"decide"})
        path["nodes"]["stark"]["requires"] = {}
        path["nodes"]["snark"]["requires"] = {"stark": "different-edge"}
        with self.assertRaisesRegex(ValueError, "statement mismatch"):
            evidence_path("wrap", path, {"decide"})

    def test_named_workflow_paths_keep_roles_and_rebuild_only_the_same_allocation(self):
        config = self.directory / "catalog.json"
        roles = {stage: {"role": role, "backend": backend} for stage, role, backend in (
            ("advance", "advance state", "script"), ("decide", "choose settlement", "script"),
        )}
        paths = {"combined": {"layout": "atomic", "stages": roles},
                 "fused": {"layout": "fused", "stages": roles},
                 "separate": {"layout": "serial", "stages": roles},
                 "stark": {"layout": "atomic", "stages": {
                     **roles, "advance": {"role": "prove the trace", "backend": "winterfell-sha256"},
                 }}}
        config.write_text(json.dumps({"workflow_paths": paths}))
        source, (_, artifact) = self.compile("atomic: advance decide ;", catalog=config)
        rows = artifact["schedule_explanation"]["candidates"]
        self.assertEqual(rows["path/combined"]["plan_sha256"], rows["atomic/script"]["plan_sha256"])
        self.assertEqual(rows["path/combined"]["stage_roles"][0]["role"], "advance state")
        self.assertEqual(rows["path/fused"]["plan_sha256"], rows["fused/script"]["plan_sha256"])
        self.assertFalse(rows["path/separate"]["eligible"])
        self.assertEqual(rows["path/stark"]["exclusions"][0]["code"], "workflow_path_unavailable")
        _, rebuilt = rebuild_candidate(source, artifact, "path/combined", self.directory, config)
        self.assertEqual(rebuilt["plan_sha256"], rows["path/combined"]["plan_sha256"])
        roles["decide"]["role"] = "different allocation"
        config.write_text(json.dumps({"workflow_paths": paths}))
        with self.assertRaisesRegex(CompileError, "candidate artifacts changed"):
            rebuild_candidate(source, artifact, "path/combined", self.directory, config)


if __name__ == "__main__":
    unittest.main()

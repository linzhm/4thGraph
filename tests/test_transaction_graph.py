"""Compiler transaction graph schema, source locations and bound outpoints."""

from dataclasses import replace
from pathlib import Path
import unittest

from fourthgraph.compiler.source import CompileError, ParentOutput, SourceCompiler, parse, schedule
from fourthgraph.workflow.protocol import Contracts
from fourthgraph.replay.workflow import EXAMPLE, GATED_EXAMPLE, TestKeys, stack_peaks
from fourthgraph.bsv.transaction import Input, Transaction
from fourthgraph.workflow.transaction_graph import mermaid
from fourthgraph.workflow.workflow_contract import WorkflowContracts, compile_workflow
from fourthgraph.replay.typed_workflow import SOURCE

EXAMPLES = Path(__file__).resolve().parents[1] / "projects/workflow-examples"
SERIAL = EXAMPLES / "serial-graph.fth"
FORK = EXAMPLES / "fork-join-graph.fth"


class TransactionGraphTests(unittest.TestCase):
    def test_invalid_source_edges_point_to_the_offending_token(self):
        source = SOURCE.read_text()
        cases = (
            (source.replace("decide decide next", "decide decide current"), "illegal repeated consumption of 'current'"),
            (source.replace("decide decide next route", "decide advance next next"), "duplicate producer of 'next'"),
        )
        for raw, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(CompileError, "line .*" + message):
                SourceCompiler(raw, source_path=SOURCE).workflow()

    def test_same_graph_schema_for_linear_parallel_and_gated(self):
        keys = TestKeys().public
        linear = WorkflowContracts(SourceCompiler(SOURCE.read_text(), source_path=SOURCE).workflow(), keys, 19, mode="atomic")
        artifacts = [linear.artifact(SOURCE.read_bytes())]
        for path in (EXAMPLE, GATED_EXAMPLE):
            program = parse(path.read_text())
            layouts = [("fused", "auto"), ("split", "auto")]
            if program.gate is not None:
                layouts.append(("split", "separate"))
            for mode, boundary in layouts:
                plan = schedule(program, mode, gate_boundary=boundary)
                artifacts.append(Contracts(plan, keys, bytes(32)).describe())
        for artifact in artifacts:
            graph = artifact["transaction_graph"]
            self.assertEqual(graph["schema_version"], 1)
            deploy, *spends = graph["transactions"]
            self.assertEqual(deploy["step"], "deploy")
            self.assertEqual([item["step"] for item in spends], [item["name"] for item in artifact["templates"]])
            names = {item["name"] for item in graph["stages"]}
            self.assertEqual({name for tx in spends for name in tx["executes"]}, names)
            for step in spends:
                self.assertIn("actual-successors", step["guards"])
        self.assertEqual(artifacts[0]["transaction_graph"]["transactions"][1]["inputs"], [
            {"from": {"step": "deploy", "vout": 0}, "authorizers": ("operator",)},
            {"from": {"step": "deploy", "vout": 1}, "authorizers": ("bob",)},
        ])

    def test_fork_graph_reports_producers_slots_and_refund_conflicts(self):
        program = parse(FORK.read_text())
        merged = schedule(program, "split", gate_boundary="merged").graph
        separate = schedule(program, "split", gate_boundary="separate").graph
        self.assertEqual(merged.stages, separate.stages)
        graph = separate.describe(recovery=program.recovery)
        joins = [edge for edge in graph["dependencies"] if edge["consumer"] == "route"]
        self.assertEqual([edge["producer"] for edge in joins], ["a", "b"])
        controls = [edge for edge in graph["dependencies"] if edge["producer"] == "prepare"]
        self.assertEqual([edge["consumer"] for edge in controls], ["a", "b"])
        self.assertTrue(all(edge["type"] == "guard" for edge in controls))
        refund = next(item for item in graph["refunds"] if item["from"] == {"step": "a", "vout": 0})
        self.assertEqual(refund["conflicts_with"], "route")
        diagram = mermaid(graph)
        self.assertIn('(("split:0 · work"))', diagram)
        self.assertIn('["refund · review · locktime 180"]', diagram)
        for output, message in ((ParentOutput("a", 1), "cannot spend data output a:1"),
                                (ParentOutput("a", 0), "illegal repeated consumption of a:0"),
                                (ParentOutput("a", 2), "no preceding output a:2")):
            with self.subTest(output=output), self.assertRaisesRegex(CompileError, "line .*" + message):
                join = separate.templates[-1]
                bad = replace(join, inputs=(join.inputs[0], output))
                replace(separate, templates=(*separate.templates[:-1], bad))

    def test_three_stages_bind_two_verified_state_outpoints(self):
        source = SERIAL.read_bytes()
        workflow = SourceCompiler(source.decode()).workflow()
        keys = TestKeys()
        artifact, report = compile_workflow(workflow, keys.public, 9, source_bytes=source, target="both", search=True)
        self.assertEqual(report["selected"], "serial")
        self.assertEqual(report["candidates"]["atomic"]["exclusions"][0]["code"], "unsupported_stage_count")
        self.assertEqual([item["producer"] for item in artifact["dependencies"]], ["increment", "scale"])
        contract = WorkflowContracts(workflow, keys.public, 9, target="both")
        root = Transaction((Input(bytes(32), 0),), contract.deployment_outputs)
        done = {"deploy": root}
        for template in contract.plan.templates:
            draft = contract.prepare(template.name, done)
            signed = draft.seal(keys.sign)
            stack_peaks(signed, draft.previous)
            evidence = draft.binding_evidence(signed)
            self.assertEqual(evidence["inputs"][0]["outpoint"], draft.previous[0].outpoint.text())
            done[template.name] = signed
        self.assertEqual(draft.payload, ((done["increment"].serialize(), done["scale"].serialize()),))
        self.assertEqual(done["decide"].outputs, (contract.terminals[1], contract.receipt(root.txid_wire(), 20)))


if __name__ == "__main__":
    unittest.main()

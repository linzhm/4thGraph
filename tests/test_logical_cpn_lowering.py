"""Executable lowering must preserve all accepted logical CPN requirements."""

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fourthgraph.bsv.evaluate import ScriptError, evaluate as evaluate_script
from fourthgraph.bsv.script import encode_num
from fourthgraph.compiler.lowering import OPTIMIZATIONS, compile_word
from fourthgraph.replay.workflow import TestKeys
from fourthgraph.verification.circuit_backend import emit_stage_circuit
from fourthgraph.workflow.logical_cpn import CPNError
from fourthgraph.workflow.logical_cpn_lowering import lower_linear
from fourthgraph.workflow.proof_planner import compile_evidence_plans

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "projects/proof-counter/workflow.fth"
SOURCE = "REQUIRE BSV\nREQUIRE counter.fth\n"
PRIVATE_SOURCE = SOURCE + """
range: private-delta u32 1 5 ;
: decide-with-delta ( u32 u32 -- route )
    check-range private-delta u32+ decide ;
"""


def document():
    return {
        "schema_version": 1,
        "places": [
            {"name": "current", "type": "u32", "initial": 1, "capacity": 1,
             "metadata": {"visibility": "public"}},
            {"name": "next", "type": "u32", "capacity": 1},
            {"name": "route", "type": "route", "capacity": 1},
        ],
        "transitions": [
            {"name": "advance", "word": "advance",
             "inputs": [{"name": "state", "place": "current", "type": "u32"}],
             "outputs": [{"name": "result", "place": "next", "type": "u32"}],
             "metadata": {"authorization": ["operator"]}},
            {"name": "decide", "word": "decide",
             "inputs": [{"name": "state", "place": "next", "type": "u32"}],
             "outputs": [{"name": "result", "place": "route", "type": "route"}],
             "metadata": {"authorization": ["bob"]}},
        ],
    }


def external_witness_document(visibility):
    graph = document()
    graph["places"].append({"name": "delta-value", "type": "u32", "initial": 1, "capacity": 1,
                            "metadata": {"carrier": "external-witness", "visibility": visibility}})
    terminal = graph["transitions"][-1]
    terminal["word"] = "decide-with-delta"
    terminal["inputs"].append({"name": "delta", "place": "delta-value", "type": "u32"})
    terminal["metadata"]["constraints"] = [{"kind": "range", "operand": "delta", "range": "private-delta"}]
    terminal["metadata"]["evidence"] = ([{"policy": "require-zk"}] if visibility == "private" else
                                      [{"policy": "require-proof", "assignment_disclosure": "allow"}])
    return graph


class LogicalCPNLoweringTests(unittest.TestCase):
    def test_external_witness_port_lowers_to_identical_proof_abi(self):
        for visibility in ("public", "private"):
            graph = external_witness_document(visibility)
            port_frontend, port_source = lower_linear(graph, PRIVATE_SOURCE, source_path=SOURCE_PATH)
            reference = deepcopy(graph)
            reference["places"].pop()
            reference["transitions"][-1]["inputs"].pop()
            reference["transitions"][-1]["metadata"]["witnesses"] = [
                {"name": "delta", "type": "u32", "visibility": visibility}]
            reference_frontend, reference_source = lower_linear(reference, PRIVATE_SOURCE, source_path=SOURCE_PATH)
            with self.subTest(visibility=visibility):
                self.assertEqual(port_source, reference_source)
                port_stage = port_frontend.workflow().stages[-1]
                self.assertEqual(port_stage.private, visibility == "private")
                self.assertEqual(emit_stage_circuit(port_stage),
                                 emit_stage_circuit(reference_frontend.workflow().stages[-1]))
                self.assertEqual([name.name for name, _ in port_stage.witnesses], ["delta"])

    def test_external_witness_rejects_unbound_or_ambiguous_graphs(self):
        changes = (
            lambda doc: doc["places"][-1]["metadata"].update(carrier="utxo"),
            lambda doc: doc["places"][-1]["metadata"].pop("visibility"),
            lambda doc: doc["places"][-1].update(initial=0),
            lambda doc: doc["places"][-1].update(capacity=2),
            lambda doc: doc["transitions"][-1]["inputs"].pop(),
            lambda doc: doc["transitions"][-1]["inputs"].reverse(),
            lambda doc: doc["transitions"][-1]["inputs"][-1].update(count=2),
            lambda doc: doc["transitions"][-1]["inputs"][-1].update(name="STATE"),
            lambda doc: doc["transitions"][-1]["metadata"].update(witnesses=[
                {"name": "delta", "type": "u32", "visibility": "private"}]),
        )
        for change in changes:
            doc = external_witness_document("private")
            change(doc)
            with self.subTest(doc=doc), self.assertRaises(CPNError):
                lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)
        doc = external_witness_document("private")
        extra = doc["transitions"][-1]["inputs"].pop()
        doc["transitions"][0]["inputs"].append(extra)
        with self.assertRaisesRegex(CPNError, "only the terminal transition"):
            lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)
        doc = external_witness_document("private")
        doc["transitions"][0]["inputs"].append(deepcopy(doc["transitions"][-1]["inputs"][-1]))
        with self.assertRaisesRegex(CPNError, "cannot be reused"):
            lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)

    def plan(self, document):
        frontend, generated = lower_linear(document, SOURCE, source_path=SOURCE_PATH)
        with TemporaryDirectory() as directory:
            contract, artifact = compile_evidence_plans(
                frontend, TestKeys().public, 19, directory, mode="auto", target="both",
                optimization="stack", objective="path-bytes", available_authorizers=None,
                sighash_family="bip143",
            )
        return generated, contract, artifact.get("schedule_explanation", artifact)

    def test_transaction_grouping_reaches_planner(self):
        doc = document()
        doc["transitions"][0]["metadata"]["atomic_with"] = ["decide"]
        doc["transitions"][1]["metadata"]["atomic_with"] = ["ADVANCE"]
        generated, contract, report = self.plan(doc)
        self.assertEqual(generated.count("atomic: advance decide ;"), 1)
        self.assertIsNotNone(contract)
        self.assertIn("atomicity_required", [item["code"] for item in
                                             report["candidates"]["serial/script"]["exclusions"]])
        self.assertTrue(report["candidates"]["fused/script"]["eligible"])
        self.assertTrue(report["candidates"]["atomic/script"]["eligible"])

        independent = document()
        independent["transitions"][1]["metadata"]["independent_submit"] = True
        generated, contract, report = self.plan(independent)
        self.assertIn("independent-submit: decide ;", generated)
        self.assertIsNotNone(contract)
        self.assertTrue(report["candidates"]["serial/script"]["eligible"])
        for mode in ("fused", "atomic"):
            self.assertIn("independent_submit", [item["code"] for item in
                                                 report["candidates"][f"{mode}/script"]["exclusions"]])

        doc["transitions"][1]["metadata"]["independent_submit"] = True
        _, contract, report = self.plan(doc)
        self.assertIsNone(contract)
        self.assertIsNone(report["selected"])
        self.assertIn("atomicity_required", [item["code"] for item in
                                             report["candidates"]["serial/script"]["exclusions"]])
        self.assertIn("independent_submit", [item["code"] for item in
                                             report["candidates"]["fused/script"]["exclusions"]])

    def test_transaction_grouping_rejects_bad_requirements(self):
        for value in ("decide", ["missing"], ["advance"], [None], [""]):
            doc = document()
            doc["transitions"][0]["metadata"]["atomic_with"] = value
            with self.subTest(atomic_with=value), self.assertRaises(CPNError):
                lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        for value in ("true", 1, None, []):
            doc = document()
            doc["transitions"][0]["metadata"]["independent_submit"] = value
            with self.subTest(independent_submit=value), self.assertRaises(CPNError):
                lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        with self.assertRaisesRegex(CPNError, "must not contain transaction declarations"):
            lower_linear(document(), SOURCE + "atomic: advance decide ;\n", source_path=SOURCE_PATH)

    def test_generated_workflow_compiles_fused_and_serial(self):
        frontend, generated = lower_linear(document(), SOURCE, source_path=SOURCE_PATH)
        self.assertIn("stage: advance advance current next operator ;", generated)
        self.assertIn("stage: decide decide next route bob ;", generated)
        self.assertEqual([stage.name for stage in frontend.workflow().stages], ["advance", "decide"])
        with TemporaryDirectory() as directory:
            _, artifact = compile_evidence_plans(
                frontend, TestKeys().public, 19, directory, mode="auto", target="both",
                optimization="stack", objective="path-bytes", available_authorizers=None, sighash_family="bip143",
            )
        candidates = artifact["schedule_explanation"]["candidates"]
        self.assertTrue(candidates["fused/script"]["eligible"])
        self.assertTrue(candidates["serial/script"]["eligible"])

    def test_unimplemented_requirements_cannot_be_silently_lost(self):
        base = document()
        for metadata in ({"authorization": ["operator"], "constraints": ["state must be valid"]},
                         {"authorization": ["operator"], "evidence": [{"backend": "groth16"}]},
                         {"authorization": ["operator"], "witnesses": ["secret"]},
                         {"authorization": ["operator"], "atomic": True},
                         {"authorization": ["operator", "alice"]}):
            doc = deepcopy(base)
            doc["transitions"][0]["metadata"] = metadata
            with self.subTest(metadata=metadata), self.assertRaises(CPNError):
                lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        for metadata in ({"visibility": "private"}, {"visibility": "public", "carrier": "utxo"}):
            doc = deepcopy(base)
            doc["places"][0]["metadata"] = metadata
            with self.subTest(metadata=metadata), self.assertRaises(CPNError):
                lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        for capacity in (2, None):
            doc = deepcopy(base)
            doc["places"][1]["capacity"] = capacity
            with self.subTest(capacity=capacity), self.assertRaisesRegex(CPNError, "explicit capacity of one"):
                lower_linear(doc, SOURCE, source_path=SOURCE_PATH)

    def test_private_witness_and_zk_policy_reach_proof_planner(self):
        doc = document()
        terminal = doc["transitions"][-1]
        terminal["word"] = "decide-with-delta"
        terminal["metadata"]["witnesses"] = [{"name": "delta", "type": "u32", "visibility": "private"}]
        terminal["metadata"]["evidence"] = [{"policy": "require-zk"}]
        terminal["metadata"]["constraints"] = [{"kind": "range", "operand": "delta", "range": "private-delta"}]
        frontend, generated = lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)
        self.assertIn("private-witness: decide delta u32 ;", generated)
        self.assertIn("policy: decide require-zk ;", generated)
        self.assertTrue(frontend.workflow().stages[-1].private)
        with TemporaryDirectory() as directory:
            contract, report = compile_evidence_plans(
                frontend, TestKeys().public, 19, directory, mode="auto", target="both",
                optimization="stack", objective="path-bytes", available_authorizers=None, sighash_family="bip143",
            )
        self.assertIsNone(contract)
        for method in ("script", "r1cs"):
            reasons = report["candidates"][f"fused/{method}"]["exclusions"]
            self.assertIn("private_witness_disclosure", [reason["code"] for reason in reasons])
        self.assertIn("missing_setup",
                      [reason["code"] for reason in report["candidates"]["fused/groth16-bls12-381"]["exclusions"]])

    def test_transparent_proof_policy_and_public_witness_are_preserved(self):
        doc = document()
        terminal = doc["transitions"][-1]
        terminal["word"] = "decide-with-delta"
        terminal["metadata"]["witnesses"] = [{"name": "delta", "type": "u32", "visibility": "public"}]
        terminal["metadata"]["evidence"] = [{"policy": "require-proof", "assignment_disclosure": "allow"}]
        terminal["metadata"]["constraints"] = [{"kind": "range", "operand": "delta", "range": "private-delta"}]
        frontend, generated = lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)
        self.assertIn("witness: decide delta u32 ;", generated)
        self.assertIn("policy: decide require-proof ;", generated)
        self.assertIn("assignment-disclosure: decide allow ;", generated)
        stage = frontend.workflow().stages[-1]
        self.assertFalse(stage.private)
        self.assertTrue(stage.assignment_disclosure)
        self.assertEqual(stage.policy, "require-proof")
        circuit, public = emit_stage_circuit(stage)
        self.assertEqual(public, ("route", "state", "bindLo", "bindHi", "witness0"))
        self.assertLess(circuit.index(b"signal input bindHi;"), circuit.index(b"signal input witness0;"))

    def test_range_constraint_requires_actual_unconditional_check_on_the_declared_operand(self):
        doc = document()
        terminal = doc["transitions"][-1]
        terminal["word"] = "decide-with-delta"
        terminal["metadata"]["witnesses"] = [{"name": "delta", "type": "u32", "visibility": "private"}]
        terminal["metadata"]["evidence"] = [{"policy": "require-zk"}]
        constraint = {"kind": "range", "operand": "delta", "range": "private-delta"}
        terminal["metadata"]["constraints"] = [constraint]
        lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)
        for replacement in ({"kind": "range", "operand": "state", "range": "private-delta"},
                            {"kind": "range", "operand": "delta", "range": "missing"},
                            {"kind": "range", "operand": "delta", "range": "private-delta", "verify": False},
                            "delta must be small"):
            terminal["metadata"]["constraints"] = [replacement]
            with self.subTest(constraint=replacement), self.assertRaises(CPNError):
                lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)
        terminal["metadata"]["constraints"] = [constraint]
        missing = PRIVATE_SOURCE.replace("check-range private-delta u32+ decide", "u32+ decide")
        with self.assertRaisesRegex(CPNError, "must begin with the matching check-range"):
            lower_linear(doc, missing, source_path=SOURCE_PATH)
        changed_bounds = PRIVATE_SOURCE.replace(
            "range: private-delta u32 1 5 ;",
            "range: private-delta u32 1 5 ;\nrange: other-delta u32 2 5 ;",
        ).replace("check-range private-delta", "check-range other-delta")
        with self.assertRaisesRegex(CPNError, "must begin with the matching check-range"):
            lower_linear(doc, changed_bounds, source_path=SOURCE_PATH)
        conditional = PRIVATE_SOURCE.replace(
            "check-range private-delta u32+ decide",
            "dup #2 cell>u32 u32< IF check-range private-delta ELSE check-range private-delta THEN u32+ decide",
        )
        with self.assertRaisesRegex(CPNError, "must begin with the matching check-range"):
            lower_linear(doc, conditional, source_path=SOURCE_PATH)

    def test_range_boundaries_survive_all_script_optimizations(self):
        doc = document()
        terminal = doc["transitions"][-1]
        terminal["word"] = "decide-with-delta"
        terminal["metadata"]["witnesses"] = [{"name": "delta", "type": "u32", "visibility": "private"}]
        terminal["metadata"]["evidence"] = [{"policy": "require-zk"}]
        terminal["metadata"]["constraints"] = [{"kind": "range", "operand": "delta", "range": "private-delta"}]
        frontend, _ = lower_linear(doc, PRIVATE_SOURCE, source_path=SOURCE_PATH)
        word = frontend.workflow().stages[-1].word
        for optimization in OPTIMIZATIONS:
            script = compile_word(word, optimization).script
            for delta in (1, 4):
                with self.subTest(optimization=optimization, delta=delta):
                    stack, alt = evaluate_script(script, [encode_num(19), encode_num(delta)])
                    self.assertEqual(stack, [encode_num(1)])
                    self.assertEqual(alt, [])
            for delta in (0, 5):
                with self.subTest(optimization=optimization, delta=delta), self.assertRaises(ScriptError):
                    evaluate_script(script, [encode_num(19), encode_num(delta)])

    def test_rejects_unknown_evidence_and_nonterminal_witness(self):
        for evidence in ([{"policy": "require-zk", "recursive": True}],
                         [{"policy": "require-zk", "assignment_disclosure": "allow"}],
                         [{"policy": "require-zk"}, {"policy": "require-proof"}]):
            doc = document()
            doc["transitions"][-1]["metadata"]["evidence"] = evidence
            with self.subTest(evidence=evidence), self.assertRaises(CPNError):
                lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        doc = document()
        doc["transitions"][0]["metadata"]["witnesses"] = [
            {"name": "delta", "type": "u32", "visibility": "private"}]
        with self.assertRaisesRegex(CPNError, "terminal transition"):
            lower_linear(doc, SOURCE, source_path=SOURCE_PATH)

    def test_rejects_branch_multiplicity_and_transaction_declarations(self):
        doc = document()
        doc["places"].append({"name": "other", "type": "u32", "capacity": 1})
        doc["transitions"][0]["outputs"].append({"name": "other", "place": "other", "type": "u32"})
        with self.assertRaisesRegex(CPNError, "one input and one output"):
            lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        doc = document()
        doc["transitions"][0]["inputs"][0]["count"] = 2
        with self.assertRaisesRegex(CPNError, "one token"):
            lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        with self.assertRaisesRegex(CPNError, "must not contain transaction declarations"):
            lower_linear(document(), SOURCE + "workflow-input: other u32 ;\n", source_path=SOURCE_PATH)

    def test_rejects_case_collision_and_wrong_word_effect(self):
        doc = document()
        doc["places"][1]["name"] = "CURRENT"
        doc["transitions"][0]["outputs"][0]["place"] = "CURRENT"
        doc["transitions"][1]["inputs"][0]["place"] = "CURRENT"
        with self.assertRaisesRegex(CPNError, "unique ignoring case"):
            lower_linear(doc, SOURCE, source_path=SOURCE_PATH)
        doc = document()
        doc["transitions"][0]["word"] = "decide"
        with self.assertRaisesRegex(CPNError, "needs u32, found route"):
            lower_linear(doc, SOURCE, source_path=SOURCE_PATH)


if __name__ == "__main__":
    unittest.main()

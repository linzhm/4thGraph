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


class LogicalCPNLoweringTests(unittest.TestCase):
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

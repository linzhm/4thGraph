"""Evidence inventory never upgrades a model declaration into proof."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fourthgraph.workflow.logical_evidence import inventory
from fourthgraph.workflow.logical_cpn import CPNError
from fourthgraph.workflow.logical_cpn_lowering import lower_linear


def recursive_model():
    return {
        "schema_version": 1,
        "places": [
            {"name": "before", "type": "state", "initial": 1,
             "metadata": {"carrier": "utxo", "fields": ["origin", "balance"]}},
            {"name": "proof", "type": "proof", "initial": 1},
            {"name": "after", "type": "state", "metadata": {"carrier": "utxo"}},
        ],
        "transitions": [{
            "name": "step", "inputs": [
                {"name": "old", "place": "before", "type": "state"},
                {"name": "prior", "place": "proof", "type": "proof"},
            ], "outputs": [{"name": "new", "place": "after", "type": "state"}],
            "metadata": {
                "constraints": ["conservation"], "authorization": ["owner"],
                "forth_source": ": step ;", "recursive_requirements": "preserve origin",
                "witnesses": ["previous transaction"],
                "evidence": [{"kind": "proof", "backend": "groth16", "verified": True}],
                "recursion": {"previous_proof": "prior", "previous_state": "old", "next_state": "new",
                              "origin_field": "origin", "base_case": "step"},
            },
        }],
    }


class EvidenceInventoryTests(unittest.TestCase):
    def test_inventory_is_only_a_declaration_even_with_claimed_verification(self):
        report = inventory(recursive_model())
        self.assertEqual(report["scope"], "logical-declarations-only")
        self.assertEqual(report["status"], "declared")
        self.assertEqual(report["transitions"][0]["status"], "declared")
        self.assertEqual(report["transitions"][0]["recursion"]["previous_proof"], "prior")
        self.assertEqual(report["transitions"][0]["recursive_requirements"], "preserve origin")
        self.assertEqual(report["transitions"][0]["forth_source"], ": step ;")
        self.assertEqual(report["places"][0]["carrier"], "utxo")
        self.assertEqual(report["diagnostics"], [])
        self.assertIn("proof verification", report["not_checked"])

    def test_recursive_ports_must_exist_on_the_correct_side(self):
        doc = recursive_model()
        doc["transitions"][0]["metadata"]["recursion"]["previous_proof"] = "new"
        doc["transitions"][0]["metadata"]["recursion"]["next_state"] = "old"
        report = inventory(doc)
        self.assertEqual([x["code"] for x in report["diagnostics"]],
                         ["unknown_recursion_port", "unknown_recursion_port"])
        doc2 = deepcopy(doc)
        del doc2["transitions"][0]["metadata"]["recursion"]["base_case"]
        self.assertIn("missing_recursion_field", [x["code"] for x in inventory(doc2)["diagnostics"]])

    def test_cli_json_and_exit_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = Path(temporary) / "model.json"
            doc = recursive_model()
            model.write_text(json.dumps(doc))
            command = [sys.executable, "-m", "fourthgraph.workflow.protocol", "cpn", "inspect-evidence", str(model)]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "declared")
            doc["transitions"][0]["metadata"]["recursion"]["previous_proof"] = "wrong-port"
            model.write_text(json.dumps(doc))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertEqual(report["diagnostics"][0]["code"], "unknown_recursion_port")
            self.assertEqual(report["status"], "declared")

    def test_base_transition_must_exist(self):
        doc = recursive_model()
        doc["transitions"][0]["metadata"]["recursion"]["base_case"] = "missing"
        self.assertEqual(inventory(doc)["diagnostics"][0]["code"], "unknown_recursion_base")

    def test_recursive_example_is_an_inspectable_but_unlowered_draft(self):
        path = Path(__file__).resolve().parents[1] / "projects/workflow-examples/recursive-lineage-model.json"
        document = json.loads(path.read_text())
        report = inventory(document)
        self.assertEqual(report["diagnostics"], [])
        self.assertEqual(report["transitions"][1]["recursion"]["base_case"], "issue")
        self.assertIn("recursive relation", report["not_checked"])
        with self.assertRaises(CPNError):
            lower_linear(document, "")

    def test_opaque_existing_evidence_remains_valid(self):
        doc = recursive_model()
        doc["transitions"][0]["metadata"].pop("recursion")
        doc["transitions"][0]["metadata"]["evidence"] = ["PELS assertion", {"policy": "require-zk"}]
        row = inventory(doc)["transitions"][0]
        self.assertEqual(row["evidence"][0], "PELS assertion")
        self.assertIsNone(row["recursion"])


if __name__ == "__main__":
    unittest.main()

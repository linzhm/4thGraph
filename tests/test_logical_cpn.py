"""Logical CPN validation and bounded token-count abstraction."""

import json
import unittest

from fourthgraph.workflow.logical_cpn import analyze, parse_net, validate_document


def sample():
    return {
        "schema_version": 1,
        "places": [
            {"name": "wallet", "type": "token", "initial": 2,
             "metadata": {"visibility": "public", "carrier": "utxo"}},
            {"name": "paid", "type": "token"},
        ],
        "transitions": [{
            "name": "transfer", "word": "transfer-rule",
            "inputs": [{"name": "coins", "place": "wallet", "type": "token", "count": 2}],
            "outputs": [{"name": "change", "place": "wallet", "type": "token"},
                        {"name": "payment", "place": "paid", "type": "token"}],
            "metadata": {"constraints": ["conserve"], "authorization": [{"role": "owner"}],
                         "evidence": [{"backend": "groth16", "recursive": True}]},
        }],
    }


class LogicalCPNTests(unittest.TestCase):
    def test_multi_port_count_and_bounded_analysis(self):
        net = parse_net(sample())
        canonical = net.describe()
        self.assertEqual(parse_net(json.loads(json.dumps(canonical))).describe(), canonical)
        self.assertEqual(canonical["transitions"][0]["metadata"]["evidence"][0]["backend"], "groth16")
        result = analyze(net)
        self.assertTrue(result["complete"])
        self.assertEqual([state["marking"] for state in result["states"]],
                         [{"wallet": 2, "paid": 0}, {"wallet": 1, "paid": 1}])
        self.assertEqual(result["edges"], [{"from": 0, "to": 1, "transition": "transfer"}])
        self.assertEqual(result["deadlocks"], [1])
        self.assertEqual(result["never_enabled"], [])
        self.assertFalse(result["may_cycle"])
        self.assertIn("guards", result["ignored"])

    def test_competing_transitions_and_loop_are_valid(self):
        doc = sample()
        doc["places"][0]["initial"] = 1
        original = doc["transitions"][0]
        original["inputs"][0]["count"] = 1
        original["outputs"] = original["outputs"][:1]
        doc["transitions"].append({
            "name": "exit",
            "inputs": [{"name": "in", "place": "wallet", "type": "token"}],
            "outputs": [{"name": "out", "place": "paid", "type": "token"}],
        })
        result = analyze(parse_net(doc))
        self.assertEqual(result["edges"], [{"from": 0, "to": 0, "transition": "transfer"},
                                            {"from": 0, "to": 1, "transition": "exit"}])
        self.assertEqual(result["deadlocks"], [1])
        self.assertTrue(result["complete"])
        self.assertTrue(result["may_cycle"])

    def test_cutoff_is_not_reported_as_a_deadlock_or_unreachable(self):
        doc = sample()
        doc["transitions"][0]["inputs"] = []
        doc["transitions"][0]["outputs"] = [{"name": "mint", "place": "wallet", "type": "token"}]
        token_bound = analyze(parse_net(doc), max_tokens_per_place=2)
        self.assertFalse(token_bound["complete"])
        self.assertEqual(token_bound["cutoffs"][0]["reason"], "token_bound")
        self.assertEqual(token_bound["deadlocks"], [])
        self.assertIsNone(token_bound["never_enabled"])
        self.assertIsNone(token_bound["may_cycle"])
        state_bound = analyze(parse_net(doc), max_states=1, max_tokens_per_place=3)
        self.assertEqual(state_bound["cutoffs"][0]["reason"], "state_budget")
        self.assertEqual(state_bound["deadlocks"], [])

    def test_capacity_is_a_semantic_limit(self):
        doc = sample()
        doc["places"][0]["capacity"] = 2
        doc["transitions"][0]["inputs"] = []
        doc["transitions"][0]["outputs"] = [{"name": "mint", "place": "wallet", "type": "token"}]
        result = analyze(parse_net(doc), max_tokens_per_place=2)
        self.assertTrue(result["complete"])
        self.assertEqual(result["deadlocks"], [0])
        self.assertEqual(result["never_enabled"], ["transfer"])

    def test_rejects_duplicate_consumption_type_mismatch_and_invalid_metadata(self):
        doc = sample()
        doc["transitions"][0]["inputs"].append({"name": "again", "place": "wallet", "type": "token"})
        result = validate_document(doc)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"][0]["code"], "duplicate_arc")
        self.assertEqual(result["diagnostics"][0]["path"], "$.transitions[0].inputs[1].place")
        doc = sample()
        doc["transitions"][0]["outputs"][1]["type"] = "u32"
        self.assertEqual(validate_document(doc)["diagnostics"][0]["code"], "type_mismatch")
        doc = sample()
        doc["transitions"][0]["metadata"]["constraints"] = "unstructured"
        self.assertEqual(validate_document(doc)["diagnostics"][0]["code"], "invalid_array")
        doc = sample()
        doc["transitions"][0]["inputs"][0]["count"] = True
        self.assertEqual(validate_document(doc)["diagnostics"][0]["code"], "invalid_count")
        doc = sample()
        doc["places"][0]["metadata"]["inner"] = {1: "not a JSON key"}
        self.assertEqual(validate_document(doc)["diagnostics"][0]["code"], "invalid_metadata")


if __name__ == "__main__":
    unittest.main()

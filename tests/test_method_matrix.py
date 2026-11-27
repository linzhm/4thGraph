import unittest

from fourthgraph.benchmark.method_matrix import IneligibleMethod, Method, explore_pairs


class MethodMatrixTests(unittest.TestCase):
    def test_ordered_pairs_keep_illegal_steps_and_distinct_plan_identity(self):
        def specialize(state):
            return (*state, "specialized") if "specialized" not in state else state

        def schedule(state):
            return (*state, "scheduled")

        def compact(state):
            if "specialized" not in state:
                raise IneligibleMethod("needs specialization")
            return (*state, "compact")

        methods = {
            "specialize": Method("kernel", "fixed input", specialize),
            "schedule": Method("kernel", "typed", schedule),
            "compact": Method("table", "specialized", compact),
        }
        result = explore_pairs({"generic": ()}, methods, describe=list,
                               evaluate=lambda _: {"status": "verified", "artifact": "same"})["generic"]
        rows = {tuple(cell["order"]): cell for cell in result["cells"]}
        self.assertEqual(len(rows), 9)
        self.assertEqual(result["baseline"]["order"], [])
        self.assertEqual(rows["specialize", "specialize"]["steps"][1]["status"], "no_change")
        self.assertEqual(rows["compact", "specialize"]["steps"], [
            {"method": "compact", "status": "ineligible", "reason": "needs specialization"},
        ])
        first = rows["specialize", "schedule"]
        second = rows["schedule", "specialize"]
        self.assertEqual(first["artifact"], second["artifact"])
        self.assertNotEqual(first["steps"][-1]["state"], second["steps"][-1]["state"])
        self.assertEqual(rows["specialize", "compact"]["status"], "verified")

    def test_rejects_oversized_matrix_before_evaluation(self):
        methods = {str(i): Method("region", "ready", lambda state: state) for i in range(9)}
        with self.assertRaisesRegex(ValueError, "between 1 and 64 cells"):
            explore_pairs({"base": 0}, methods, describe=str, evaluate=self.fail)

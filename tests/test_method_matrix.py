import unittest

from fourthgraph.benchmark.method_matrix import explore_pairs
from fourthgraph.compiler.method_search import IneligibleMethod, Method, explore_orders


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

    def test_order_search_revisits_a_method_when_the_state_changes(self):
        def fold(state):
            return {0: 1, 2: 3}.get(state, state)

        def expose(state):
            if state != 1:
                raise IneligibleMethod("needs first fold")
            return 2

        methods = {"fold": Method("formula", "typed", fold), "expose": Method("formula", "folded", expose)}
        report = explore_orders(0, methods, describe=str,
                                evaluate=lambda _: {"status": "verified", "artifact": "same bytes"})
        self.assertEqual(report["stop"], "exhausted")
        self.assertEqual([row["order"] for row in report["states"]], [
            [], ["fold"], ["fold", "expose"], ["fold", "expose", "fold"],
        ])
        self.assertIn({"from": 0, "method": "expose", "status": "ineligible", "reason": "needs first fold"},
                      report["transitions"])
        self.assertIn({"from": 1, "method": "fold", "status": "no_change", "to": 1}, report["transitions"])

    def test_order_search_records_convergence_and_bounds_separately(self):
        methods = {"a": Method("state", "ready", lambda s: s | 1),
                   "b": Method("state", "ready", lambda s: s | 2)}
        options = {"describe": int, "evaluate": lambda _: {"status": "verified"}}
        report = explore_orders(0, methods, **options)
        self.assertEqual(len(report["states"]), 4)
        self.assertIn({"from": 2, "method": "a", "status": "equivalent", "to": 3}, report["transitions"])
        depth = explore_orders(0, methods, max_depth=1, **options)
        self.assertEqual((depth["stop"], depth["limits_hit"], len(depth["states"])), ("budget", ["depth"], 3))
        budget = explore_orders(0, methods, max_states=1, **options)
        self.assertEqual((budget["stop"], budget["limits_hit"], len(budget["states"])), ("budget", ["states"], 1))
        with self.assertRaisesRegex(ValueError, "method search depth"):
            explore_orders(0, methods, max_depth=True, **options)

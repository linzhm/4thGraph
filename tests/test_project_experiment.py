import json
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from itertools import product
import unittest
from unittest.mock import patch

from fourthgraph.benchmark.experiment import capabilities, digest, next_request, run
from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, encode_num, number
from fourthgraph.compiler.formula_experiment import enumerate_orders
from fourthgraph.compiler.script_builder import ScriptBuilder


class FormulaExperiments(unittest.TestCase):
    def test_cross_axis_baseline_uses_the_same_compiler_plan(self):
        first = run({"fixture": "bezier", "plans": [{}, {"passes": ["stack"]}]})
        _, stack = first["candidates"]
        self.assertEqual(first["baseline_bytes"], 118)
        request = {"fixture": "bezier", "axis": "B", "parent_run": first["run_id"], "plans": [
            {"implementation": "bezier-linear", "passes": ["stack"], "parent_id": stack["id"]},
        ]}
        second = run(request, first)
        self.assertEqual(second["baseline"]["id"], stack["id"])
        self.assertEqual(second["baseline_bytes"], 47)
        self.assertEqual(second["candidates"][0]["delta"]["baseline_bytes"], -10)

        linear, = second["candidates"]
        third = run({"fixture": "bezier", "axis": "A", "parent_run": second["run_id"], "plans": [
            {"implementation": "bezier-linear", "passes": ["stack", "search"], "parent_id": linear["id"]},
        ]}, second)
        self.assertIsNone(third["baseline"])
        self.assertIsNone(third["candidates"][0]["delta"]["baseline_bytes"])

        first["baseline_bytes"] = 1
        with self.assertRaisesRegex(ValueError, "parent run"):
            run(request, first)

    def test_matching_baseline_survives_multiple_batches(self):
        first = run({"fixture": "bezier", "plans": [{}, {"passes": ["stack"]}]})
        second = run(next_request(first), first)
        parent, = second["candidates"]
        request = {"fixture": "bezier", "parent_run": second["run_id"], "plans": [
            {"passes": ["rewrite", "stack"], "parent_id": parent["id"]},
        ]}
        third = run(request, second)
        self.assertEqual(third["baseline"], first["baseline"])
        self.assertEqual(third["baseline_bytes"], 118)
        second["baseline"]["bytes"] = 1
        with self.assertRaisesRegex(ValueError, "parent run"):
            run(request, second)

    def test_distinct_parents_keep_distinct_candidate_ids(self):
        initial = run({"fixture": "bezier", "plans": [{}, {"passes": ["stack"]}]})
        second = run({"fixture": "bezier", "parent_run": initial["run_id"], "plans": [
            {"passes": ["stack", "search"], "parent_id": row["id"]} for row in initial["candidates"]
        ]}, initial)
        left, right = second["candidates"]
        self.assertEqual(left["artifact"]["sha256"], right["artifact"]["sha256"])
        self.assertNotEqual(left["id"], right["id"])
        self.assertNotEqual(left["delta"]["parent_bytes"], right["delta"]["parent_bytes"])
        self.assertCountEqual(second["ranking"], (left["id"], right["id"]))
        self.assertEqual(second["run_id"], run(second["request"], initial)["run_id"])

    def test_deadline_bounds_admission_and_replay_keeps_admitted_candidates(self):
        request = {"fixture": "square", "time_ms": 1, "plans": [{}, {"passes": ["stack"]}]}
        cases = (
            (0, [0, .001, .001]),
            (1, [0, 0, .001, .001]),
            (2, [0, 0, 0, .001]),
        )
        for admitted, ticks in cases:
            with self.subTest(admitted=admitted):
                with patch("fourthgraph.benchmark.experiment.monotonic", side_effect=ticks):
                    report = run(request)
                self.assertEqual(report["stop"], "time_budget")
                self.assertEqual(len(report["candidates"]), admitted)
                with patch("fourthgraph.benchmark.experiment.monotonic", side_effect=AssertionError):
                    replay = run(report["request"], replaying=True)
                self.assertEqual(replay["run_id"], report["run_id"])

    def test_axis_b_uses_canonical_pass_sets_and_ordered_rules(self):
        request = {"fixture": "bezier", "axis": "B", "plans": [
            {"passes": ["stack", "share"]},
            {"implementation": "bezier-linear", "passes": ["share", "stack"]},
        ]}
        report = run(request)
        self.assertEqual([row["applied"]["passes"] for row in report["candidates"]], [["share", "stack"]] * 2)
        request["plans"][0]["rules"] = ["double-as-add", "common-values"]
        request["plans"][1]["rules"] = ["common-values", "double-as-add"]
        with self.assertRaisesRegex(ValueError, "axis B freezes the compiler plan"):
            run(request)

    def test_two_batches_keep_equal_size_parents_and_replay(self):
        first = run({"fixture":"bezier","workers":2,"plans":[{},{"passes":["stack"]},{"passes":["rewrite","share","stack"]}]})
        self.assertEqual([r["artifact"]["bytes"] for r in first["candidates"]],[118,47,47])
        next_plan = next_request(json.loads(json.dumps(first)))
        second = run(next_plan,first)
        self.assertEqual([r["delta"]["parent_bytes"] for r in second["candidates"]],[0,-1])
        self.assertEqual([r["test"]["passed"] for r in first["candidates"]+second["candidates"]],[625]*5)
        self.assertEqual(second["run_id"],run(second["request"],first)["run_id"])
        self.assertEqual(len(capabilities()["plan_sets"]),12)
        first["candidates"][1]["artifact"]["sha256"]="bad"
        with self.assertRaisesRegex(ValueError,"parent run"):
            run(next_plan,first)

    def test_stack_trace_describes_only_the_selected_schedule_and_is_replayed(self):
        request = {"fixture": "bezier", "workers": 2, "trace": True,
                   "plans": [{}, {"passes": ["stack"]}, {"passes": ["rewrite", "share", "stack"]}]}
        first = run(request)
        follow = next_request(first)
        self.assertTrue(follow["trace"])
        second = run(follow, first)
        rows = first["candidates"] + second["candidates"]
        plans = [row["trace"]["target_stack_plan"] for row in rows]
        self.assertEqual([p["order"] for p in plans], ["source", "source", "source", "source", "beam"])
        self.assertEqual(plans[-2]["steps"], plans[1]["steps"])
        self.assertNotEqual(plans[-1]["steps"], plans[2]["steps"])
        for row, plan in zip(rows, plans, strict=True):
            code = bytes.fromhex(row["artifact"]["hex"])
            boundaries = {item["offset"] for item in row["artifact"]["instructions"]} | {len(code)}
            formula = row["trace"]["formula_snapshots"][-1]
            operations = {"int+": asm("OP_ADD"), "int-": asm("OP_SUB"), "int*": asm("OP_MUL")}
            definitions = {plan["formula_slots"][node["id"]]: node for node in formula["steps"]}

            def markers(slots):
                return [encode_num(slot + 1) for slot in slots]

            state = plan["inputs"]
            offset = 0
            for step in plan["steps"]:
                self.assertEqual(step["before"], state)
                self.assertEqual(step["offset"], offset)
                end = offset + step["bytes"]
                operation = step["operation_offset"]
                self.assertTrue({offset, operation, end} <= boundaries)
                self.assertTrue(offset <= operation < end)
                node = definitions[step["slot"]]
                args = [plan["formula_slots"][i] for i in node["args"]]
                opcode = code[operation:end]
                if opcode == asm("OP_DUP OP_ADD"):
                    self.assertEqual(node["op"], "int*")
                    self.assertIn(step["args"][0], args)
                    self.assertIn(2, [formula["steps"][i]["immediate"] for i in node["args"]])
                else:
                    expected = number(node["immediate"]) if node["op"] == "literal" else operations[node["op"]]
                    self.assertEqual(opcode, expected)
                    self.assertEqual(step["args"], args)
                if opcode == asm("OP_SUB"):
                    self.assertEqual(step["args"], step["operands"])
                else:
                    self.assertCountEqual(step["args"], step["operands"])

                staged = step["after"][:-1] + step["operands"]
                self.assertEqual(evaluate(code[offset:operation], markers(state)), (markers(staged), []))
                state = step["after"]
                self.assertEqual(state[-1], step["slot"])
                offset = end
            finish = plan["finish"]
            self.assertEqual(finish["before"], state)
            self.assertEqual(finish["after"], plan["returns"])
            self.assertEqual(finish["offset"], offset)
            self.assertEqual(offset + finish["bytes"], row["artifact"]["bytes"])
            self.assertEqual(evaluate(code[offset:], markers(state)), (markers(plan["returns"]), []))
            self.assertEqual([plan["formula_slots"][i] for i in formula["returns"]], plan["returns"])
        self.assertEqual(run(second["request"], first)["run_id"], second["run_id"])
        first["candidates"][1]["trace"]["target_stack_plan"]["steps"][0]["offset"] += 1
        with self.assertRaisesRegex(ValueError, "parent run"):
            run(follow, first)

    def test_cli_agent_and_fixed_square_replay(self):
        def call(cmd,data):
            result=subprocess.run([sys.executable,"-m","fourthgraph.workflow.protocol","experiment",cmd,"-"],
                                  input=json.dumps(data),text=True,capture_output=True,check=True)
            return json.loads(result.stdout)
        first=call("run", {"fixture":"square","plans":[{},{"passes":["stack"]}]})
        self.assertEqual([r["artifact"]["bytes"] for r in first["candidates"]],[6,3])
        second=run(call("next",first), first)
        self.assertEqual(second["candidates"][0]["test"]["passed"],11)
        self.assertEqual(second["candidates"][0]["delta"]["parent_bytes"],0)
        self.assertEqual(second["winner_including_parents"],first["ranking"][0])
        self.assertEqual(call("next",second)["stop"],"no_improving_expansion")
        self.assertEqual(call("replay",first)["run_id"],first["run_id"])

    def test_replay_and_follow_up_verify_formula_trace(self):
        report = run({"fixture": "square", "trace": True, "plans": [{}, {"passes": ["stack"]}]})
        saved = json.dumps(report)
        follow_up = next_request(report)
        command = [sys.executable, "-m", "fourthgraph.workflow.protocol", "experiment", "replay", "-"]

        replay = subprocess.run(command, input=saved, text=True, capture_output=True, check=True)
        original = json.loads(saved)
        replayed = json.loads(replay.stdout)
        self.assertEqual(replayed["run_id"], report["run_id"])
        self.assertEqual(replayed["candidates"][1]["trace"], original["candidates"][1]["trace"])
        self.assertEqual(run(follow_up, original)["candidates"][0]["test"]["status"], "passed")

        for change in ("changed bounds", "missing trace"):
            with self.subTest(change=change):
                edited = json.loads(saved)
                candidate = edited["candidates"][1]
                if change == "changed bounds":
                    candidate["trace"]["formula_snapshots"][0]["steps"][0]["bounds"] = [0, 1000]
                else:
                    del candidate["trace"]
                replay = subprocess.run(command, input=json.dumps(edited), text=True, capture_output=True)
                self.assertEqual(replay.returncode, 2, replay.stderr)
                self.assertIn("formula traces", json.loads(replay.stdout)["diagnostic"])
                with self.assertRaisesRegex(ValueError, "parent run"):
                    run(follow_up, edited)

    def _require_pinned_chain(self):
        try:
            pinned = chain_metadata()["commit"] == CONTEXT_PIN
        except PackageNotFoundError:
            pinned = False
        if not pinned:
            self.skipTest("requires pinned chain-gang")

    def test_spend_receipts_measure_and_replay_the_same_compiler_plans(self):
        self._require_pinned_chain()
        request = {"fixture": "square", "evaluation": "spend", "workers": 2,
                   "plans": [{}, {"passes": ["stack"]}]}
        first = run(request)
        baseline, optimized = first["candidates"]
        self.assertEqual(first["frozen"]["spend"]["commit"], CONTEXT_PIN)
        self.assertEqual(baseline["source_sha256"], optimized["source_sha256"])
        for row in first["candidates"]:
            self.assertEqual(row["test"]["status"], "passed")
            receipt = row["test"]["spend"]
            self.assertEqual((receipt["accepted"], receipt["rejected"]), (11, 11))
            sizes = row["metrics"]
            self.assertEqual(sizes["path_bytes"], sizes["funding_transaction_bytes"] + sizes["transaction_bytes"])
        self.assertEqual(first["ranking"][0], optimized["id"])
        self.assertEqual(optimized["delta"]["baseline_path_bytes"], -3)
        follow = next_request(json.loads(json.dumps(first)))
        self.assertEqual(follow["evaluation"], "spend")
        second = run(follow, first)
        self.assertEqual(second["candidates"][0]["delta"]["parent_path_bytes"], 0)
        self.assertEqual(second["winner_including_parents"], optimized["id"])
        self.assertEqual(run(second["request"], first)["run_id"], second["run_id"])
        with self.assertRaisesRegex(ValueError, "frozen snapshot mismatch"):
            run({**follow, "evaluation": "formula"}, first)

    def test_bezier_spend_checks_both_outputs_and_replays_the_search_delta(self):
        self._require_pinned_chain()
        self.assertIn("bezier", capabilities()["evaluations"]["spend"]["fixtures"])
        first = run({"fixture": "bezier", "evaluation": "spend", "workers": 3, "trace": True,
                     "plans": [{}, {"passes": ["stack"]}, {"passes": ["rewrite", "share", "stack"]}]})
        follow = next_request(json.loads(json.dumps(first)))
        self.assertEqual(len(follow["plans"]), 2)
        second = run(follow, first)
        rows = first["candidates"] + second["candidates"]
        self.assertEqual([row["metrics"]["script_bytes"] for row in rows], [118, 47, 47, 47, 46])
        self.assertNotEqual(rows[1]["id"], rows[2]["id"])
        self.assertEqual([row["requested"]["parent_id"] for row in second["candidates"]],
                         [rows[1]["id"], rows[2]["id"]])
        self.assertEqual(len({row["source_sha256"] for row in rows}), 1)
        for row in rows:
            receipt = row["test"]["spend"]
            self.assertEqual((row["test"]["passed"], receipt["accepted"], receipt["rejected"]), (625, 625, 625))
            self.assertEqual(row["test"]["status"], "passed")
            path_max = max(case["bytes"]["funding_transaction_bytes"] + case["bytes"]["transaction_bytes"]
                           for case in receipt["cases"])
            self.assertEqual(row["metrics"]["path_bytes"], path_max)
        self.assertEqual([row["metrics"]["path_bytes"] for row in rows], [260, 189, 189, 189, 188])
        examples = {case["operands"]: case for case in rows[-1]["test"]["spend"]["cases"]}
        endpoint = examples[(0, 0, 0, 0)]
        self.assertEqual(endpoint["expected_outputs"], (0, 0))
        self.assertEqual(endpoint["rejected_operands"], (0, 1, 0, 0))
        interior = examples[(0, 0, 0, 8)]
        self.assertEqual(interior["expected_outputs"], (0, 0))
        self.assertEqual(interior["rejected_operands"], (1, 1, 1, 8))
        self.assertEqual([row["delta"]["parent_path_bytes"] for row in second["candidates"]], [0, -1])
        self.assertEqual(second["winner_including_parents"], rows[-1]["id"])
        self.assertEqual(run(second["request"], first)["run_id"], second["run_id"])

    def test_spend_mode_requires_pinned_engine_and_a_passing_receipt(self):
        request = {"fixture": "square", "evaluation": "spend", "plans": [{}]}
        with patch("fourthgraph.benchmark.spend_fixture.chain_metadata", return_value={"commit": None}):
            with self.assertRaisesRegex(ValueError, "requires pinned chain-gang"):
                run(request)
        with patch("fourthgraph.benchmark.spend_fixture.chain_metadata",
                   return_value={"version": "test", "commit": CONTEXT_PIN}), patch(
                       "fourthgraph.benchmark.experiment.check_spends",
                       return_value={"status": "failed", "diagnostic": "fixture rejection"}):
            report = run(request)
        row, = report["candidates"]
        self.assertEqual(row["compile"]["status"], "passed")
        self.assertEqual(row["test"]["formula_status"], "passed")
        self.assertEqual(row["test"]["status"], "failed")
        self.assertEqual(row["test"]["spend"]["diagnostic"], "fixture rejection")
        self.assertEqual(report["ranking"], [])

    def test_spend_engine_error_does_not_count_as_a_rejected_witness(self):
        self._require_pinned_chain()
        request = {"fixture": "square", "evaluation": "spend", "plans": [{}]}
        with patch("fourthgraph.bsv.chain_gang.validate_at_heights",
                   side_effect=[None, RuntimeError("engine unavailable")]):
            report = run(request)
        row, = report["candidates"]
        receipt = row["test"]["spend"]
        self.assertEqual((receipt["status"], receipt["expected"], receipt["observed"]),
                         ("failed", "rejected", "error"))
        self.assertEqual(receipt["diagnostic"], "engine unavailable")
        self.assertEqual(report["ranking"], [])

    def test_invalid_candidates_and_limits(self):
        report=run({"fixture":"square","plans":[{"passes":["search"]},{},{"passes":[]}]})
        self.assertEqual(report["candidates"][0]["test"]["status"],"not_run")
        self.assertIn("requires stack",report["candidates"][0]["compile"]["diagnostic"])
        self.assertEqual(report["deduplicated_plans"],1)
        for changes in ({"workers":5},{"snapshot":"changed"},{"plans":[{}]*33},{"axis":"B","plans":[{},{"passes":["stack"]}]}):
            with self.assertRaises(ValueError):
                run({"fixture":"square","plans":[{}],**changes})
        ordered=run({"fixture":"square","plans":[{"rules":["stack","double-as-add"]}]})
        self.assertEqual(ordered["candidates"][0]["compile"]["status"],"failed")

    def test_ordered_rules_recompute_and_preserve_origins(self):
        source="""REQUIRE BSV
        range: a script-int 0 11 ;
        range: out script-int 0 41 ;
        formula: both ( a -- out ) {: x :}
            2 x int* let left
            x x int+ let right
            left right int+
        ;"""
        def build(rules):
            b=ScriptBuilder(source,formula_passes=["stack"],experimental_rules=rules,trace_formulas=True)
            return b.formula_snapshots["both"], b.emit("both",b"")
        a,b="double-as-add","common-values"
        left,code1=build([a,b])
        right,code2=build([b,a])
        repeated,code3=build([b,a,b])
        self.assertLess(len(left[-1]["steps"]),len(right[-1]["steps"]))
        self.assertEqual(repeated[-1],left[-1])
        origins=[{loc["word"] for loc in s["origins"]} for s in left[-1]["steps"]]
        self.assertTrue(any({"left","right"}<=names for names in origins))
        for code,n in product((code1,code2,code3),range(11)):
            self.assertEqual(evaluate(code,[encode_num(n)]),([encode_num(4*n)],[]))
        ir=ScriptBuilder(source).formula_ir["both"]
        self.assertIn((a,b), list(enumerate_orders(ir)))

    def test_algorithm_axis_and_trace(self):
        plans=[{"passes":["stack"],"implementation":i} for i in ("bezier","bezier-linear")]
        base=run({"fixture":"bezier","axis":"B","plans":plans})
        traced=run({"fixture":"bezier","axis":"B","plans":plans,"trace":True})
        self.assertEqual([r["artifact"]["bytes"] for r in base["candidates"]],[47,37])
        self.assertEqual([r["artifact"]["sha256"] for r in base["candidates"]],
                         [r["artifact"]["sha256"] for r in traced["candidates"]])
        self.assertNotEqual(*[r["source_sha256"] for r in traced["candidates"]])
        self.assertTrue(all(r["test"]["passed"]==625 for r in base["candidates"]))
        self.assertEqual(digest(base["frozen"]),base["snapshot"])

    def test_bezier_shortlisted_plans_compare_each_algorithm_in_full_spends(self):
        self._require_pinned_chain()
        for passes, expected_path_bytes in (
            (["stack"], (189, 179)),
            (["rewrite", "share", "stack", "search"], (188, 176)),
        ):
            with self.subTest(passes=passes):
                report = run({"fixture": "bezier", "axis": "B", "evaluation": "spend", "plans": [
                    {"implementation": implementation, "passes": passes}
                    for implementation in ("bezier", "bezier-linear")
                ]})
                reference, linear = report["candidates"]
                self.assertNotEqual(reference["source_sha256"], linear["source_sha256"])
                self.assertEqual(report["baseline"]["id"], reference["id"])
                self.assertEqual(report["ranking"], [linear["id"], reference["id"]])
                self.assertEqual(tuple(row["metrics"]["path_bytes"] for row in (reference, linear)), expected_path_bytes)
                for row in (reference, linear):
                    spend = row["test"]["spend"]
                    self.assertEqual((spend["status"], spend["accepted"], spend["rejected"]), ("passed", 625, 625))

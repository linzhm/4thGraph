import json
import subprocess
import sys
from itertools import product
import unittest

from fourthgraph.benchmark.experiment import capabilities, digest, next_request, run
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import encode_num
from fourthgraph.compiler.formula_experiment import enumerate_orders
from fourthgraph.compiler.script_builder import ScriptBuilder


class FormulaExperiments(unittest.TestCase):
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

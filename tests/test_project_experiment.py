import json
from hashlib import sha256
import os
import subprocess
import sys
from importlib.metadata import PackageNotFoundError
from itertools import product
import unittest
from unittest.mock import patch

from fourthgraph.benchmark.experiment import binding_plans, capabilities, digest, next_request, run
from fourthgraph.benchmark.fixtures import ByteLayoutFixture, FIXTURES, HashChainFixture
from fourthgraph.benchmark.spend_fixture import CONTEXT, linked_spends
from fourthgraph.benchmark.validation import CONTEXT_PIN, NODE_GENESIS_FLAGS, Node, chain_metadata
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, encode_num, number
from fourthgraph.compiler.formula_experiment import RULES, enumerate_orders, transform
from fourthgraph.compiler.byte_layout import PACKED as PACKED_BYTES, REPEAT as REPEAT_BYTES
from fourthgraph.compiler.hash_chain import PAIRS, SINGLE, HashChainBuilder
from fourthgraph.compiler.point_add import AFFINE, GENERAL, GUARDED, PointAddBuilder
from fourthgraph.compiler.ranges import Slot
from fourthgraph.benchmark.point_add_fixture import PointAddFixture
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.script_formula import GENESIS_NUM_BYTES, Formula, Step


EQUALVERIFY_REJECTION = "Script failed an OP_EQUALVERIFY operation"
FALSE_TOP_REJECTION = "Script evaluated without error but finished with a false/empty top stack element"


class FormulaExperiments(unittest.TestCase):
    def test_byte_layout_composes_distinct_bindings_and_respects_the_payload_budget(self):
        self._require_pinned_chain()
        request = {"fixture": "byte-layout", "evaluation": "spend", "enumerate": "binding-combinations"}
        report = run(request)
        base, packed, repeat, combined = report["candidates"]
        self.assertEqual(len({row["source_sha256"] for row in report["candidates"]}), 1)
        self.assertEqual([row["metrics"]["path_bytes"] for row in report["candidates"]], [1720, 1090, 1542, 912])
        self.assertEqual([row["metrics"]["peak_payload_bytes"] for row in report["candidates"]], [425, 617, 425, 617])
        self.assertEqual(report["ranking"][0], combined["id"])
        self.assertIn("peak_payload_bytes", report["frontier_costs"])
        for row in (base, packed, repeat, combined):
            receipt = row["test"]["spend"]
            self.assertEqual((receipt["status"], receipt["accepted"], receipt["rejected"]), ("passed", 24, 24))
            script = bytes.fromhex(row["artifact"]["hex"])
            for site in row["compile"]["lowering"]["call_sites"]:
                start = site["offset"]
                self.assertEqual(site["linked_sha256"], sha256(script[start:start + site["bytes"]]).hexdigest())
        reverse_site, mask_site, single_site, irregular_site = combined["compile"]["lowering"]["call_sites"]
        self.assertEqual((reverse_site["kernel"], mask_site["kernel"]), (PACKED_BYTES, REPEAT_BYTES))
        self.assertEqual(reverse_site["evidence"]["checked_input_bytes"], 192)
        self.assertEqual((mask_site["evidence"]["seed_bytes"], mask_site["evidence"]["doublings"]), (3, 6))
        self.assertFalse(single_site["candidates"][1]["eligible"])
        self.assertFalse(irregular_site["candidates"][1]["eligible"])

        bounded = run({**request, "max_payload_bytes": 500})
        self.assertEqual(bounded["baseline_path_bytes"], 1720)
        self.assertEqual(bounded["ranking"], [repeat["id"], base["id"]])
        self.assertEqual(bounded["winner_including_parents"], repeat["id"])
        self.assertEqual(bounded["candidates"][-1]["selection"], {"eligible": False, "reason": "payload_budget_exceeded"})
        self.assertEqual(run(bounded["request"], replaying=True)["run_id"], bounded["run_id"])
        self.assertEqual(run({**request, "max_payload_bytes": 424})["ranking"], [])
        self.assertEqual(len(run({**request, "max_payload_bytes": 617})["ranking"]), 4)

    def test_byte_layout_excludes_bindings_without_matching_width_and_contents(self):
        report = run({"fixture": "byte-layout", "plans": [
            {"bindings": [{"site": 2, "kernel": PACKED_BYTES}]},
            {"bindings": [{"site": 3, "kernel": REPEAT_BYTES}]},
            {"bindings": [{"site": 0, "kernel": REPEAT_BYTES}]},
        ]})
        self.assertEqual(report["ranking"], [])
        for row, message in zip(report["candidates"], ("exactly six", "identical halves", "wrong operation"), strict=True):
            self.assertEqual(row["compile"]["status"], "failed")
            self.assertIn(message, row["compile"]["diagnostic"])

    def test_binding_combinations_keep_one_kernel_per_site_and_obey_the_candidate_limit(self):
        choices = [{"kernel": name, "eligible": True} for name in ("base", "a", "b")]
        sites = [{"site": site, "kernel": "base", "candidates": choices} for site in (0, 0, 1)]
        plans = list(binding_plans(sites, combine=True))
        self.assertEqual([len(row.get("bindings", ())) for row in plans], [0, 1, 1, 1, 1, 2, 2, 2, 2])
        self.assertTrue(all(len({row["site"] for row in p["bindings"]}) == 2 for p in plans[-4:]))
        report = run({"fixture": "byte-layout", "enumerate": "binding-combinations", "max_candidates": 3})
        self.assertEqual(report["stop"], "candidate_budget")
        self.assertEqual(len(report["candidates"]), 3)

    def test_payload_budget_survives_follow_up_and_is_verified_during_replay(self):
        report = run({"fixture": "square", "plans": [{}, {"passes": ["stack"]}], "max_payload_bytes": 50})
        request = next_request(report)
        self.assertEqual(request["max_payload_bytes"], 50)
        with self.assertRaisesRegex(ValueError, "keep the parent's max_payload_bytes"):
            run({**request, "max_payload_bytes": 51}, report)
        self.assertEqual(run(request, report)["winner_including_parents"], report["ranking"][0])
        report["request"]["max_payload_bytes"] = 51
        result = subprocess.run([sys.executable, "-m", "fourthgraph.workflow.protocol", "experiment", "replay", "-"],
                                input=json.dumps(report), text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(os.environ.get("REGTEST_COOKIE"), "requires tools/verify_node.sh")
    def test_byte_layout_spends_and_malformed_fields_match_both_engines(self):
        from fourthgraph.bsv.chain_gang import validate_at_heights

        self._require_pinned_chain()
        fixture = ByteLayoutFixture()
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        report = run({"fixture": fixture.name, "evaluation": "spend", "enumerate": "binding-combinations"})
        for row in report["candidates"]:
            self.assertEqual(row["test"]["status"], "passed")
            script = bytes.fromhex(row["artifact"]["hex"])
            for case, parent, spend, rejected in linked_spends(fixture, script):
                self.assertEqual(node.verdicts(spend, (parent,), **CONTEXT), [True], case)
                changed_short = case["operands"][0] != case["rejected_operands"][0]
                expected_rejection = FALSE_TOP_REJECTION if changed_short else EQUALVERIFY_REJECTION
                self.assertEqual(node.verdicts(rejected, (parent,), **CONTEXT,
                                               expected_rejection=expected_rejection), [False], case)
            for short, wide in ((31, 192), (33, 192), (32, 191), (32, 193)):
                witness = fixture.encode(bytes(short).hex()) + fixture.encode(bytes(wide).hex())
                malformed = spend.with_script(0, witness)
                self.assertEqual(node.verdicts(malformed, (parent,), **CONTEXT,
                                               expected_rejection="Script failed an OP_NUMEQUALVERIFY operation"),
                                 [False], (short, wide))
                with self.assertRaisesRegex(ValueError, r"^Error evaluating the script `Numbers are not equal`$"):
                    validate_at_heights(malformed, (parent,), **CONTEXT)

    def test_modular_rules_reduce_a_full_spend_with_the_same_source(self):
        self._require_pinned_chain()
        report = run({"fixture": "modular-dot", "enumerate": "orders", "trace": True, "evaluation": "spend"})
        rows = report["candidates"]
        index = {row["id"]: row for row in rows}
        winner = index[report["ranking"][0]]
        self.assertEqual(len({row["source_sha256"] for row in rows}), 1)
        self.assertEqual(len(rows), 9)
        self.assertEqual(report["baseline_path_bytes"], 245)
        self.assertEqual(rows[1]["metrics"]["path_bytes"], 202)
        self.assertEqual(winner["metrics"]["path_bytes"], 187)
        self.assertEqual(winner["applied"]["rules"], list(RULES[-3:]))
        self.assertEqual(winner["compile"]["lowering"]["ordered_rules"], [
            {"rule": "fold-literals", "applications": 2},
            {"rule": "factor-products", "applications": 2},
            {"rule": "elide-redundant-remainder", "applications": 1},
        ])
        self.assertEqual(winner["metrics"]["peak_payload_bytes"], 44)
        for row, multiply, remainder in ((rows[1], 5, 2), (winner, 2, 1)):
            instructions = [entry["op"] for entry in row["artifact"]["instructions"]]
            self.assertEqual((instructions.count("OP_MUL"), instructions.count("OP_MOD")), (multiply, remainder))
        for row in rows:
            spend = row["test"]["spend"]
            self.assertEqual((spend["status"], spend["accepted"], spend["rejected"]), ("passed", 96, 96))
        follow = run(next_request(report), report)
        self.assertEqual(follow["winner_including_parents"], winner["id"])
        self.assertEqual(run(follow["request"], report)["run_id"], follow["run_id"])
        self.assertEqual(run(report["request"])["run_id"], report["run_id"])

    def test_constant_and_remainder_rules_preserve_signed_boundaries(self):
        source = """REQUIRE BSV
        range: inexact script-int -10 11 ;
        range: narrow script-int -9 10 ;
        formula: exact ( inexact -- narrow narrow ) {: x :}
            -13 5 int-rem
            x 10 int-rem 10 int-rem
        ;
        formula: identity ( narrow -- narrow ) {: x :}
            x 10 int-rem
        ;
        """
        builder = ScriptBuilder(source, formula_passes=["stack"],
                                experimental_rules=["fold-literals", "elide-redundant-remainder"])
        code = builder.emit("exact", b"")
        self.assertEqual(builder.emit("identity", b""), b"")
        for x, result in ((-10, 0), (-9, -9), (0, 0), (9, 9), (10, 0)):
            self.assertEqual(evaluate(code, [encode_num(x)]), ([encode_num(-3), encode_num(result)], []))
        unsafe = source.replace("-13 5 int-rem", "-13 0 int-rem")
        with self.assertRaisesRegex(ValueError, "positive divisor"):
            ScriptBuilder(unsafe, formula_passes=["stack"], experimental_rules=["fold-literals"])

    def test_factorization_keeps_original_when_new_intermediate_is_too_wide(self):
        bound = 1 << (GENESIS_NUM_BYTES * 8 - 2)
        wide = Slot("script-int", (bound, bound))
        zero = Slot("script-int", (0, 0))
        steps = (Step("input", wide), Step("input", wide), Step("literal", zero, immediate=0),
                 Step("int*", zero, (2, 0)), Step("int*", zero, (2, 1)), Step("int+", zero, (3, 4)))
        formula = Formula(2, steps, (5,), ((),) * len(steps))
        self.assertEqual(transform(formula, "factor-products"), formula)

    def test_order_enumeration_reports_the_candidate_limit(self):
        orders = [*product(RULES, repeat=3)]
        with patch("fourthgraph.benchmark.experiment.enumerate_orders", return_value=iter(orders)):
            report = run({"fixture": "square", "enumerate": "orders"})
        self.assertEqual(len(report["candidates"]), 32)
        self.assertEqual(report["stop"], "candidate_budget")
        self.assertEqual(report["baseline"]["applied"]["passes"], [])
        self.assertEqual(run(report["request"], replaying=True)["run_id"], report["run_id"])

    @unittest.skipUnless(os.environ.get("REGTEST_COOKIE"), "requires tools/verify_node.sh")
    def test_modular_spends_match_regtest(self):
        self._require_pinned_chain()
        report = run({"fixture": "modular-dot", "enumerate": "orders", "evaluation": "spend"})
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        for row in report["candidates"]:
            self.assertEqual(row["test"]["status"], "passed")
            script = bytes.fromhex(row["artifact"]["hex"])
            for case, parent, spend, rejected in linked_spends(FIXTURES["modular-dot"], script):
                self.assertEqual(node.verdicts(spend, (parent,), **CONTEXT), [True], case)
                self.assertEqual(node.verdicts(rejected, (parent,), **CONTEXT,
                                               expected_rejection=FALSE_TOP_REJECTION), [False], case)

    def test_large_matrix_keeps_the_smallest_linked_plan(self):
        self._require_pinned_chain()
        report = run({"fixture": "matrix-mul", "axis": "B", "evaluation": "spend", "trace": True, "plans": [
            {"passes": ["stack", "search"]},
            {"implementation": "matrix-mul-strassen", "passes": ["stack", "search"]},
        ]})
        direct, strassen = report["candidates"]
        self.assertEqual(report["ranking"][0], direct["id"])
        self.assertNotEqual(direct["source_sha256"], strassen["source_sha256"])
        for row, multiplications in ((direct, 8), (strassen, 7)):
            self.assertEqual(row["test"]["status"], "passed")
            self.assertEqual((row["test"]["spend"]["accepted"], row["test"]["spend"]["rejected"]), (64, 64))
            self.assertEqual(sum(op["op"] == "OP_MUL" for op in row["artifact"]["instructions"]), multiplications)
            self.assertGreater(row["metrics"]["peak_payload_bytes"], 256)
        self.assertEqual([row["metrics"]["path_bytes"] for row in (direct, strassen)], [710, 753])
        same_source = run({"fixture": "matrix-mul", "evaluation": "spend", "plans": [
            {}, {"passes": ["stack"]}, {"passes": ["rewrite", "share", "stack", "search"]},
            {"passes": ["stack", "search"]},
        ]})
        base, scheduled, full, simpler = same_source["candidates"]
        self.assertEqual([row["metrics"]["path_bytes"] for row in (base, scheduled, full, simpler)],
                         [788, 712, 710, 710])
        self.assertEqual(same_source["ranking"][:2], [simpler["id"], full["id"]])

    def test_hash_chain_binds_the_long_region_and_retains_the_checkpoint(self):
        self._require_pinned_chain()
        report = run({"fixture": "hash-chain", "evaluation": "spend", "enumerate": "bindings"})
        base, paired = report["candidates"]
        self.assertEqual(report["ranking"][0], paired["id"])
        self.assertEqual(base["source_sha256"], paired["source_sha256"])
        self.assertEqual([row["metrics"]["path_bytes"] for row in (base, paired)], [4363, 4331])
        first, final = paired["compile"]["lowering"]["call_sites"]
        self.assertEqual((first["kernel"], final["kernel"]), (SINGLE, PAIRS))
        self.assertFalse(first["candidates"][1]["eligible"])
        self.assertEqual((final["evidence"]["rounds"], final["kernel_bytes"], final["adapter_bytes"]), (65, 32, 1))
        code = bytes.fromhex(paired["artifact"]["hex"])
        start = final["offset"]
        self.assertEqual(code[start:start + final["bytes"]], asm("OP_HASH256") * 32 + asm("OP_SHA256"))
        for row in (base, paired):
            self.assertEqual(row["test"]["status"], "passed")
            self.assertEqual((row["test"]["spend"]["accepted"], row["test"]["spend"]["rejected"]), (29, 29))
        self.assertEqual(run(report["request"])["run_id"], report["run_id"])

    def test_hash_chain_rejects_bindings_without_compatible_rounds(self):
        report = run({"fixture": "hash-chain", "plans": [
            {"bindings": [{"site": 0, "kernel": PAIRS}]},
            {"bindings": [{"site": 1, "kernel": AFFINE}]},
        ]})
        self.assertEqual(report["ranking"], [])
        self.assertIn("at least two", report["candidates"][0]["compile"]["diagnostic"])
        self.assertIn("wrong operation", report["candidates"][1]["compile"]["diagnostic"])
        for rounds in (0, 2, 64, 256):
            with self.subTest(rounds=rounds):
                builder = HashChainBuilder(f"REQUIRE stdlib/hash-chain.fth\n"
                                           f": fold ( script -- script ) {rounds} sha256-chain ;")
                bindings = [{"site": 0, "kernel": PAIRS}] if rounds else []
                code, _ = builder.emit_plan("fold", bindings)
                self.assertEqual(code, asm("OP_HASH256") * (rounds // 2))
        builder = HashChainBuilder("REQUIRE stdlib/hash-chain.fth\n: fold ( script -- script ) 257 sha256-chain ;")
        with self.assertRaisesRegex(ValueError, "between 0 and 256"):
            builder.emit_plan("fold", [])

    def test_hash_chain_spans_follow_repeated_fragments(self):
        source = """REQUIRE stdlib/hash-chain.fth
        : pair ( script -- script ) 2 sha256-chain ;
        : repeated ( script -- script ) op-nop bsv-empty pair 3 bsv-repeat-code bsv-cat-code ;
        """
        builder = HashChainBuilder(source)
        code, sites = builder.emit_plan("repeated", [{"site": 0, "kernel": PAIRS}])
        self.assertEqual(code, asm("OP_NOP OP_HASH256 OP_HASH256 OP_HASH256"))
        self.assertEqual([(site["site"], site["offset"], site["bytes"]) for site in sites],
                         [(0, 1, 1), (0, 2, 1), (0, 3, 1)])

    def test_node_negative_control_requires_the_expected_script_error(self):
        fixture = HashChainFixture()
        builder = fixture.builder(fixture.source(fixture.name))
        script, _ = builder.emit_plan(fixture.entry, [])
        _, parent, _, rejected = next(linked_spends(fixture, script))
        node = Node.__new__(Node)
        reply = {"result": "error", "flags": NODE_GENESIS_FLAGS,
                 "description": "Operation not valid with the current stack size"}
        with patch.object(node, "call", return_value=[reply]):
            with self.assertRaisesRegex(ValueError, "current stack size"):
                node.verdicts(rejected, (parent,), **CONTEXT, expected_rejection=EQUALVERIFY_REJECTION)
            reply["description"] = EQUALVERIFY_REJECTION
            self.assertEqual(node.verdicts(rejected, (parent,), **CONTEXT,
                                           expected_rejection=EQUALVERIFY_REJECTION), [False])

    @unittest.skipUnless(os.environ.get("REGTEST_COOKIE"), "requires tools/verify_node.sh")
    def test_large_arithmetic_and_hash_spends_match_regtest(self):
        self._require_pinned_chain()
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        matrix = FIXTURES["matrix-mul"]
        matrix_plans = [{"implementation": implementation, "passes": ["stack", "search"]}
                        for implementation in matrix.implementations]
        for fixture, options in ((matrix, {"axis": "B", "plans": matrix_plans}),
                                 (HashChainFixture(), {"enumerate": "bindings"})):
            report = run({"fixture": fixture.name, "evaluation": "spend", **options})
            for row in report["candidates"]:
                self.assertEqual(row["test"]["status"], "passed")
                script = bytes.fromhex(row["artifact"]["hex"])
                for case, parent, spend, rejected in linked_spends(fixture, script):
                    self.assertEqual(node.verdicts(spend, (parent,), **CONTEXT), [True], case)
                    self.assertEqual(node.verdicts(rejected, (parent,), **CONTEXT,
                                                   expected_rejection=EQUALVERIFY_REJECTION), [False], case)

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
        edited = json.loads(json.dumps(first))
        edited["candidates"][0]["metrics"]["path_bytes"] = 1
        command = [sys.executable, "-m", "fourthgraph.workflow.protocol", "experiment", "replay", "-"]
        replay = subprocess.run(command, input=json.dumps(edited), text=True, capture_output=True)
        self.assertEqual(replay.returncode, 2, replay.stderr)
        self.assertIn("costs", json.loads(replay.stdout)["diagnostic"])

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

    def test_point_add_spans_follow_composed_and_repeated_fragments(self):
        fixture = PointAddFixture()
        source = fixture.source(fixture.name).decode() + (
            "\n: outer ( script -- script ) op-nop bsv-empty add-two 2 bsv-repeat-code bsv-cat-code ;\n"
        )
        builder = PointAddBuilder(source)
        fragment, original = builder.emit_plan(fixture.entry, [])
        code, sites = builder.emit_plan("outer", [])
        self.assertEqual(code, asm("OP_NOP") + fragment * 2)
        self.assertEqual([site["offset"] for site in sites],
                         [1 + copy * len(fragment) + site["offset"] for copy in range(2) for site in original])
        for site in sites:
            offset = site["offset"]
            self.assertEqual(sha256(code[offset:offset + site["bytes"]]).hexdigest(), site["linked_sha256"])

    def test_point_add_enumerates_only_eligible_call_site_bindings(self):
        self._require_pinned_chain()
        self.assertEqual(capabilities()["call_site_fixtures"]["point-add"]["enumerate"], "bindings")
        report = run({"fixture": "point-add", "evaluation": "spend", "enumerate": "bindings", "workers": 2})
        base, optimized, guarded = report["candidates"]
        self.assertEqual(len({row["source_sha256"] for row in (base, optimized, guarded)}), 1)
        for row, fixed_kernel, runtime_kernel in (
            (base, GENERAL, GENERAL), (optimized, AFFINE, GENERAL), (guarded, GENERAL, GUARDED),
        ):
            fixed, runtime = row["compile"]["lowering"]["call_sites"]
            self.assertEqual((fixed["kernel"], runtime["kernel"]), (fixed_kernel, runtime_kernel))
            self.assertEqual(fixed["evidence"]["z"], 1)
            self.assertEqual(runtime["evidence"]["kind"], "runtime-projective")
            self.assertFalse(runtime["candidates"][1]["eligible"])
            emitted = bytes.fromhex(row["artifact"]["hex"])
            for site in (fixed, runtime):
                offset = site["offset"]
                self.assertEqual(site["bytes"], site["kernel_bytes"] + site["adapter_bytes"])
                self.assertEqual(site["guard_bytes"], site["adapter_bytes"] if site["kernel"] == GUARDED else 0)
                self.assertEqual(sha256(emitted[offset:offset+site["bytes"]]).hexdigest(), site["linked_sha256"])
            spend = row["test"]["spend"]
            self.assertEqual((spend["status"], spend["accepted"], spend["rejected"]), ("passed", 13, 13))
        runtime = guarded["compile"]["lowering"]["call_sites"][1]
        condition = runtime["guard"]
        self.assertEqual((condition["kind"], condition["value"]), ("canonical-scriptnum-equality", 1))
        self.assertEqual((condition["match"]["kernel"], condition["fallback"]["kernel"]), (AFFINE, GENERAL))
        script = bytes.fromhex(guarded["artifact"]["hex"])
        start = runtime["offset"]
        self.assertEqual(script[start:start + condition["match"]["relative_offset"]],
                         asm("OP_DUP OP_1 OP_EQUAL OP_IF OP_DROP"))
        for branch, direct_site in zip((condition["match"], condition["fallback"]),
                                       optimized["compile"]["lowering"]["call_sites"], strict=True):
            self.assertEqual(branch["kernel_sha256"], direct_site["kernel_sha256"])
            self.assertEqual(branch["library_sha256"], direct_site["library_sha256"])
        for branch in (condition["match"], condition["fallback"]):
            offset = runtime["offset"] + branch["relative_offset"]
            self.assertEqual(sha256(script[offset:offset+branch["kernel_bytes"]]).hexdigest(), branch["kernel_sha256"])
        self.assertEqual({case["operands"][-1] for case in guarded["test"]["spend"]["cases"]}, {0, 1, 2, 11})
        self.assertEqual([row["metrics"]["path_bytes"] for row in (base, optimized, guarded)], [789, 777, 882])
        self.assertEqual(optimized["delta"]["baseline_path_bytes"], -12)
        self.assertGreater(guarded["delta"]["baseline_path_bytes"], 0)
        self.assertEqual(report["ranking"][0], optimized["id"])
        self.assertEqual(report["run_id"], run(report["request"])["run_id"])

    def test_point_add_rejects_wrong_curve_missing_proof_and_duplicate_bindings(self):
        request = {"fixture": "point-add", "plans": [
            {"bindings": [{"site": 0, "kernel": "p256-add"}]},
            {"bindings": [{"site": 1, "kernel": AFFINE}]},
            {"bindings": [{"site": 0, "kernel": AFFINE}, {"site": 0, "kernel": GENERAL}]},
            {"bindings": [{"site": 2, "kernel": GENERAL}]},
            {"bindings": [{"site": 0, "kernel": GUARDED}]},
        ]}
        report = run(request)
        self.assertEqual(report["ranking"], [])
        for row, message in zip(report["candidates"],
                                ("wrong curve", "proven Z=1", "duplicate binding", "unknown call site",
                                 "already has a constant"), strict=True):
            self.assertEqual(row["compile"]["status"], "failed")
            self.assertIn(message, row["compile"]["diagnostic"])
            self.assertEqual(row["test"]["status"], "not_run")
        fixture = PointAddFixture()
        source = fixture.source("point-add").decode()
        x, y = fixture.generator
        encoded = f"{x:064x}{y:064x}"
        invalid = PointAddBuilder(source.replace(encoded, "00" * 64))
        with self.assertRaisesRegex(ValueError, "outside the secp256k1 curve"):
            invalid.emit_plan(fixture.entry, [{"site": 0, "kernel": AFFINE}])

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

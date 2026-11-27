"""Bounded schedule search preserves constraints and builds stable artifacts."""

from dataclasses import replace
import unittest

from fourthgraph.compiler.source import CompileError, ParentOutput, parse
from fourthgraph.workflow.protocol import check_result_sources, compile_decision, compile_search
from fourthgraph.replay.workflow import EXAMPLE, GATED_EXAMPLE, TASK_ID, TestKeys


class SearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = TestKeys().public
        cls.source = GATED_EXAMPLE.read_bytes()

    def search(self, source=None, **options):
        source = self.source if source is None else source
        return compile_search(parse(source.decode()), self.keys, TASK_ID, source_bytes=source,
                              target="both", optimization="stack", **options)

    def test_gated_search_explores_both_dimensions_and_keeps_replay_identity(self):
        contracts, artifacts, decision = self.search()
        self.assertEqual(list(artifacts), ["fused", "split-merged-full", "split-merged-shared",
                                           "split-separate-full", "split-separate-shared"])
        self.assertEqual(decision["selected"], "fused")
        _, other_artifacts, peak = self.search(objective="peak-validation")
        self.assertEqual(peak["selected"], "split-merged-shared")
        self.assertEqual(artifacts, other_artifacts)
        self.assertEqual((artifacts, decision), self.search()[1:])

        program = parse(self.source.decode())
        for name, contract in contracts.items():
            candidate = decision["candidates"][name]
            self.assertEqual(artifacts[name]["source_sha256"], artifacts["fused"]["source_sha256"])
            _, plain, _ = compile_decision(
                program, self.keys, TASK_ID, source_bytes=self.source, mode=contract.plan.mode,
                gate_boundary=candidate["gate_boundary"] or "auto", join_witness=contract.join_witness,
                target="both", optimization="stack",
            )
            self.assertEqual(plain[contract.plan.mode], artifacts[name])
            if contract.plan.mode == "split":
                parent = program.gate.name if candidate["gate_boundary"] == "separate" else "deploy"
                self.assertEqual(contract.templates["split"].inputs, (ParentOutput(parent, 0),))
                check_result_sources(contract.plan)

    def test_constraints_exclude_fusion_and_gate_merge_before_ranking(self):
        _, artifacts, decision = self.search(self.source + b"\nindependent-submit qualify\n")
        self.assertEqual(set(artifacts), {"split-separate-full", "split-separate-shared"})
        for name in ("fused", "split-merged-full", "split-merged-shared"):
            row = decision["candidates"][name]
            self.assertFalse(row["eligible"])
            self.assertNotIn("rank", row)
            self.assertEqual(row["exclusions"][0]["code"], "independent_submit")
            line = row["exclusions"][0]["line"]
            self.assertEqual((self.source + b"\nindependent-submit qualify\n").splitlines()[line - 1],
                             b"independent-submit qualify")
        with self.assertRaisesRegex(CompileError, "independent-submit"):
            self.search(self.source + b"\nindependent-submit qualify\n", gate_boundary="merged")

    def test_gated_search_reports_unavailable_inputs_and_authorizers(self):
        _, _, decision = self.search(available_data=iter(("x", "y")), available_authorizers=iter(("alice", "bob")))
        for name in ("fused", "split-merged-full"):
            self.assertEqual([row["code"] for row in decision["candidates"][name]["exclusions"]],
                             ["unavailable_input", "unavailable_authorizer"])
        self.assertEqual(decision["selected"], "split-separate-shared")
        changed_owner = self.source.replace(b"eligible operator", b"eligible alice")
        _, _, decision = self.search(changed_owner)
        self.assertEqual(decision["candidates"]["split-merged-shared"]["exclusions"][0]["code"],
                         "different_authorities")
        self.assertTrue(decision["candidates"]["split-separate-shared"]["eligible"])

    def test_parallel_and_explicit_filters(self):
        _, artifacts, _ = self.search(EXAMPLE.read_bytes())
        self.assertEqual(list(artifacts), ["fused", "split-full", "split-shared"])
        contracts, _, _ = self.search(mode="split", gate_boundary="separate", join_witness="shared")
        only, = contracts.values()
        join = only.plan.templates[-1]
        bad = replace(only.plan, templates=(*only.plan.templates[:-1], replace(join, inputs=join.inputs[::-1])))
        with self.assertRaisesRegex(CompileError, "two ordered results"):
            check_result_sources(bad)
        self.assertEqual(list(contracts), ["split-separate-shared"])


if __name__ == "__main__":
    unittest.main()

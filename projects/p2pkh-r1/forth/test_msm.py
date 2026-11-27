from importlib.metadata import PackageNotFoundError
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from comparison_report import read_report
from fixed_templates import VERSIONS_DIRECTORY
from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, push
from msm_compiler import CALIBRATION, SOURCE, R1MSMCompiler
from msm_experiment import frozen_build, local_build
from msm_lowering import reconstruction, repeat_prefix, repeat_stack, repeated
from r1_method_matrix import run_experiment


class R1MSMTests(unittest.TestCase):
    def test_published_reference_uses_versioned_bip143_measurements(self):
        report, _ = read_report(VERSIONS_DIRECTORY / "v0.6.0/comparison.json")
        costs = report["candidates"]["split-4"]["measured"]["payment_bytes"]
        self.assertEqual(costs, {"bip143-all": 84742, "otda-all": 92672, "otda-single": 92601})

    def test_scan_proves_affine_opportunity_without_lowering_a_window(self):
        compiler = R1MSMCompiler()
        report = compiler.scan(compiler.plan("split-4"))
        self.assertNotIn("optimized", vars(compiler))
        self.assertEqual(report["digit_ranges_inclusive"]["G"], [0, 15])
        self.assertEqual(report["unexpanded_counts"]["loop_adds"], 127)
        first = report["opportunities"][0]
        self.assertEqual((first["calls"], first["try"]), (64, "split-4-affine-g"))
        self.assertEqual(first["estimated"]["multiplications_removed"], 192)
        with self.assertRaisesRegex(ValueError, r"msm.fth:\d+:\d+: .*joint entries"):
            compiler.plan("joint-2-affine-g")

    def test_missing_checked_point_guard_fails_preflight(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "msm.fth"
            (path.parent / "r1.fth").write_bytes(SOURCE.with_name("r1.fth").read_bytes())
            path.write_text(SOURCE.read_text().replace("r1-prepare-lock r1-prepare-scalars",
                                                       "r1-prepare-scalars"))
            with self.assertRaisesRegex(ValueError, "does not preserve the verified point guard"):
                R1MSMCompiler(path)

    def test_calibration_and_affine_candidate_keep_lock_and_reconstruction_linked(self):
        compiler = R1MSMCompiler()
        expected = {
            "split-4": (41986, 3940),
            "joint-2": (42378, 3058),
            "split-5x4": (41721, 5510),
            "split-4-affine-g": (41474, 4067),
        }
        for name in (*CALIBRATION, "split-4-affine-g"):
            with self.subTest(candidate=name):
                (lock, pattern), report = local_build(compiler, compiler.plan(name), 12)
                self.assertEqual((len(lock.script), len(pattern.program)), expected[name])
                for owner in (bytes(20), bytes(range(20))):
                    self.assertEqual(pattern.match(lock.lock(owner)), (owner,))
                self.assertEqual(report["point_vectors"], 12)
                if name.endswith("-affine-g"):
                    cost = report["estimated"]["affine_g"]
                    self.assertEqual(cost["multiplications_removed_on_nonzero_path"], 192)
                    self.assertEqual(cost["guard_bytes_added"], 320)

    def test_frozen_template_keeps_the_reviewed_source_and_artifact(self):
        (lock, pattern), release = frozen_build()
        historical, _ = read_report(VERSIONS_DIRECTORY / "v0.6.0/comparison.json")
        self.assertEqual(release["build_source"], {field: historical[field]
                                                   for field in ("source_sha256", "dependencies")})
        self.assertEqual((len(lock.script), len(pattern.program), lock.owner_start), (41364, 5658, 208))
        for owner in (bytes(20), bytes(range(20))):
            self.assertEqual(pattern.match(lock.lock(owner)), (owner,))

    def test_scan_proposes_the_smaller_affine_guard(self):
        compiler = R1MSMCompiler()
        _, release = frozen_build()
        original = compiler.plan(release["construction"])
        baseline, _ = compiler.link(compiler.lower(original))
        scan = compiler.scan(original)
        opportunity = next(row for row in scan["opportunities"] if row["id"] == "affine-g-ifdup")
        self.assertEqual(opportunity["calls"], 51)
        self.assertEqual(opportunity["missing"], [])
        plan = compiler.plan(opportunity["try"])
        (lock, pattern), report = local_build(compiler, plan, 32)
        _, next_version = frozen_build("v0.7.0")
        self.assertEqual(report["point_vectors"], 32)
        self.assertEqual(next_version["construction"], opportunity["try"])
        self.assertTrue(report["reconstruction_byte_match"])
        self.assertEqual(pattern.match(lock.lock(bytes(20))), (bytes(20),))
        self.assertEqual(len(baseline.script) - len(lock.script), 102)
        self.assertEqual(opportunity["estimated"]["window_loop_bytes_saved"], 102)

    def test_repeat_encoders_keep_the_exact_bytes_and_altstack(self):
        for encode in (repeat_prefix, repeat_stack):
            for chunk in (b"", b"x", b"\x00value\xff"):
                for count in (1, 2, 3, 5, 7, 15, 63, 127, 128, 255):
                    with self.subTest(encode=encode.__name__, chunk=chunk, count=count):
                        code = asm("OP_TOALTSTACK") + push(chunk) + encode(count)
                        self.assertEqual(evaluate(code, [b"sentinel"]), ([chunk * count], [b"sentinel"]))
        self.assertEqual(len(repeated(127)) - len(repeat_prefix(127)), 19)
        self.assertLess(len(repeat_stack(12)), len(repeated(12)))

    def test_adjacent_kernel_packing_keeps_gaps_and_order(self):
        first, second = b"first kernel" * 5, b"second kernel" * 5
        fragment = first * 4 + b"/" + second + first
        before, after = b"start", b"end"
        parts = (b"prefix", before, ((fragment, 12),), after, (first, second))
        baseline = reconstruction(*parts)
        packed = reconstruction(*parts, stack_repeat=True, adjacent_kernels=True)
        expected = [b"prefix", before + fragment * 12 + after]
        self.assertEqual(evaluate(baseline), (expected, []))
        self.assertEqual(evaluate(packed), (expected, []))
        self.assertLess(len(packed), len(baseline))

    def test_ordered_method_matrix_verifies_pairs_and_ranks_each_target(self):
        try:
            engine = chain_metadata()
        except PackageNotFoundError:
            self.skipTest("requires pinned chain-gang")
        if engine["commit"] != CONTEXT_PIN:
            self.skipTest("requires pinned chain-gang")
        evidence = run_experiment()
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(len(evidence["artifacts"]), 9)

        def cells(seed):
            rows = evidence["matrices"][seed]["cells"]
            self.assertEqual(len(rows), 25)
            return {tuple(row["order"]): row for row in rows}

        split = cells("from_split")
        affine = cells("from_affine")
        self.assertEqual(split["compact-g", "affine-g"]["status"], "ineligible")
        self.assertEqual(split["joint-window", "affine-g"]["status"], "ineligible")
        a = split["affine-g", "point-add-stack-search"]["artifact"]
        b = split["point-add-stack-search", "affine-g"]["artifact"]
        self.assertNotEqual(a, b)
        self.assertEqual(evidence["artifacts"][a]["compile"]["lock_bytes"], 41_927)
        self.assertEqual(evidence["artifacts"][b]["compile"]["lock_bytes"], 41_315)
        shared = affine["compact-g", "ifdup"]["artifact"]
        self.assertEqual(shared, affine["ifdup", "compact-g"]["artifact"])
        self.assertEqual(evidence["rankings"]["bip143-all"][0]["artifact"], shared)
        self.assertEqual(evidence["rankings"]["otda-all"][0]["artifact"], shared)


if __name__ == "__main__":
    unittest.main()

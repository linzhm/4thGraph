"""Regression tests for Forth lowering and the transaction binding invariants."""

from dataclasses import replace
from itertools import product
from random import Random
import unittest

from shared.benchmark_validation import chain_verdict
from shared.chain_gang import validate_at_heights
from shared.evaluate import evaluate as evaluate_script
from shared.script import decode_num, encode_num
from shared.transaction import Input, Transaction

from compiler import CompileError, SourceCompiler, evaluate, lower, parse, schedule
from lowering import compile_word
from protocol import Contracts, compile_candidates, invalidated
from replay import EXAMPLE, TASK_ID, TestKeys
from wordsets import CELL_SIGN, U32, capabilities

SOURCE = EXAMPLE.read_text()


class CompilerTests(unittest.TestCase):
    def test_stack_types_and_host_location(self):
        with self.assertRaisesRegex(CompileError, "declared"):
            parse(SOURCE.replace("DUP u32+", "DUP"))
        with self.assertRaisesRegex(CompileError, "equal stack types"):
            parse(SOURCE.replace("ELSE route-settle", "ELSE 1"))
        source = "bsv-effect: fetch outpoint -- utxo ;\n: fetch bsv-lookup-utxo ;\n"
        word = SourceCompiler(source).words["fetch"]
        self.assertEqual(word.location, "host")
        with self.assertRaisesRegex(CompileError, r"bsv-lookup-utxo \(line 2, column 9\)"):
            lower(word)
        with self.assertRaisesRegex(CompileError, "host-only.*bsv-lookup-utxo"):
            parse(source + SOURCE.replace("x double alice", "x fetch alice"))

    def test_arithmetic_and_literal_lowering(self):
        source = "bsv-effect: wrap -- u32 ;\n: wrap 4294967295 cell>u32 1 cell>u32 u32+ ;\n" + SOURCE
        words = parse(source).words
        for name, values, expected in (
            ("double", (U32 - 1,), U32 - 2),
            ("inc", (U32 - 1,), 0),
            ("wrap", (), 0),
            ("decide", (15, 4), 0),
            ("decide", (15, 5), 1),
            ("decide", (U32 - 1, 1), 0),
        ):
            with self.subTest(word=name, values=values):
                self.assertEqual(evaluate(words[name], *values), (expected,))
                stack, alt = evaluate_script(lower(words[name]), [encode_num(v) for v in values])
                self.assertEqual((list(map(decode_num, stack)), alt), ([expected], []))
        self.assertEqual(lower(words["wrap"]), b"\x00")

    def test_safe_lowering_ranges_and_comparison_result(self):
        words = SourceCompiler(SOURCE + "\nbsv-effect: compare cell cell -- cell ;\n: compare < ;\n").words
        self.assertEqual([len(compile_word(words["inc"], mode).script) for mode in ("baseline", "safe")], [70, 8])
        optimized = compile_word(words["decide"], "safe")
        self.assertEqual(len(optimized.script), 16)
        change, = (item for item in optimized.rewrites if item.rule == "comparison-feeds-if")
        self.assertEqual(SOURCE.splitlines()[change.line - 1][change.column - 1:][:2], "IF")
        rng = Random(11704)
        edges = (0, 1, 19, 20, 21, 1 << 31, U32 - 2, U32 - 1)
        data = [(words["inc"], (x,)) for x in (*edges, *(rng.getrandbits(32) for _ in range(128)))]
        data += [(words["decide"], (x, y)) for x, y in product(edges, repeat=2)]
        data += [(words["compare"], (0, 1)), (words["compare"], (1, 0))]
        for word, args in data:
            expected = list(evaluate(word, *args))
            for mode in ("baseline", "safe"):
                stack, alt = evaluate_script(compile_word(word, mode).script, list(map(encode_num, args)))
                self.assertEqual((list(map(decode_num, stack)), alt), (expected, []), (args, mode))

    def test_stack_scheduling_shares_repeated_operands_and_preserves_branch_slots(self):
        source = """
bsv-effect: shared u32 u32 -- u32 ;
: shared 2DUP u32+ ROT ROT u32+ u32+ ;
bsv-effect: branch u32 u32 cell -- u32 ;
: branch IF shared ELSE SWAP DROP THEN ;
"""
        words = SourceCompiler(source).words
        shared = compile_word(words["shared"], "stack")
        self.assertTrue(any(item.rule == "stack-last-use-and-sharing" for item in shared.rewrites))
        self.assertLess(len(shared.script), len(compile_word(words["shared"], "safe").script))
        cases = [(words["shared"], (a, b)) for a, b in product((0, 7, U32 - 1), repeat=2)]
        cases += [(words["branch"], args) for args in product((0, U32 - 1), (3, 8), (0, -1))]
        for word, args in cases:
            stack, alt = evaluate_script(compile_word(word, "stack").script, list(map(encode_num, args)))
            self.assertEqual((tuple(map(decode_num, stack)), alt), (evaluate(word, *args), []))

    def test_core_cell_semantics(self):
        source = """
bsv-effect: sum cell cell -- cell ;
: SUM ( an ordinary multiline
  comment may contain unknown words ) + ;
bsv-effect: signed-less cell cell -- cell ;
: signed-less < ;
bsv-effect: unsigned-less cell cell -- cell ;
: unsigned-less U< ;
bsv-effect: guard cell cell -- cell ;
: guard IF 2 + THEN ;
bsv-effect: numerals -- cell ;
: numerals #-2 $10 + %10 + 'A' + ' ' + ;
"""
        words = SourceCompiler(source).words
        for name, args, expected in (
            ("sum", (U32 - 1, 1), U32),
            ("sum", (CELL_SIGN - 1, 1), -CELL_SIGN),
            ("sum", (-CELL_SIGN, -1), CELL_SIGN - 1),
            ("signed-less", (-1, 0), -1),
            ("unsigned-less", (-1, 0), 0),
            ("unsigned-less", (0, -1), -1),
            ("guard", (5, -7), 7),
            ("guard", (5, 0), 5),
            ("numerals", (), 113),
        ):
            with self.subTest(name=name, args=args):
                word = words[name]
                self.assertEqual(evaluate(word, *args), (expected,))
                stack, alt = evaluate_script(lower(word), list(map(encode_num, args)))
                self.assertEqual((list(map(decode_num, stack)), alt), ([expected], []))

    def test_optional_words_and_build_diagnostics(self):
        manifest = capabilities()
        self.assertIn("+", manifest["wordsets"]["core"]["script"])
        self.assertIn("execute", manifest["wordsets"]["core"]["unsupported"])
        self.assertFalse(manifest["wordsets"]["core-ext"]["enabled_by_default"])
        self.assertIn("true", manifest["wordsets"]["core-ext"]["script"])
        source = "bsv-effect: flag -- cell ;\n: flag TRUE ;"
        with self.assertRaisesRegex(CompileError, r"line 2, column 8: .*CORE EXT word 'TRUE' requires"):
            SourceCompiler(source)
        self.assertEqual(evaluate(SourceCompiler("bsv-use core-ext \\ enabled\n" + source).words["flag"]), (-1,))
        with self.assertRaisesRegex(CompileError, r"line 2, column 8: .*CORE word 'EXECUTE' cannot compile"):
            SourceCompiler(source.replace("TRUE", "EXECUTE"))
        with self.assertRaisesRegex(CompileError, "unknown Forth word 'TYPO'"):
            SourceCompiler(source.replace("TRUE", "TYPO"))
        with self.assertRaisesRegex(CompileError, "optional Forth word set 'search' is unavailable"):
            SourceCompiler("bsv-use search")
        with self.assertRaisesRegex(CompileError, "preceding 'bsv-effect:"):
            SourceCompiler(": ordinary ( cell -- cell ) 1 + ;")

    def test_schedule_constraints(self):
        program = parse(SOURCE)
        self.assertEqual(schedule(program).mode, "fused")
        plan = schedule(program, available_data=("x",), available_authorizers=("alice",))
        self.assertEqual(plan.mode, "split")
        self.assertIn("b: input y is unavailable at fusion", plan.fusion_blockers)
        self.assertIn("b: authorizer bob is unavailable at fusion", plan.fusion_blockers)
        constrained = parse(SOURCE + "\nindependent-submit a\n")
        self.assertEqual(schedule(constrained).mode, "split")
        with self.assertRaisesRegex(CompileError, rf"line {len(SOURCE.splitlines()) + 2}: independent-submit a"):
            schedule(constrained, "fused")
        self.assertEqual(schedule(parse(SOURCE + "\na independent-submit\n")).mode, "split")


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.keys = TestKeys()
        self.plan = schedule(parse(SOURCE), "split")
        self.contracts = Contracts(self.plan, self.keys.public, TASK_ID)
        deploy = Transaction((Input(bytes(32), 0),), (self.contracts.root,))
        self.done = {"deploy": deploy}
        self.split = self.contracts.prepare("split", self.done)
        self.done["split"] = self.split.seal(self.keys.sign)

    def test_rebind_after_split_txid_changes(self):
        original = self.done["split"]
        changed = replace(self.split, tx=replace(self.split.tx, locktime=1)).seal(self.keys.sign)
        self.assertEqual(invalidated(self.plan, "split", original, changed),
                         {"a": ("alice",), "b": ("bob",), "route": ()})
        self.assertEqual(invalidated(self.plan, "split", original, original), {})
        branch = self.contracts.prepare("a", self.done, {"x": 10})
        signature = self.keys.sign(branch.signing_requests()[0])
        rebound = self.contracts.prepare("a", {**self.done, "split": changed}, {"x": 10})
        self.assertNotEqual(branch.signing_requests()[0].outpoint, rebound.signing_requests()[0].outpoint)
        self.assertNotEqual(branch.signing_requests()[0].digest, rebound.signing_requests()[0].digest)
        self.assertTrue(chain_verdict(rebound.seal(self.keys.sign), rebound.parents))
        self.assertFalse(chain_verdict(rebound.seal(lambda _request: signature), rebound.parents))

    def test_branch_commitment_and_real_result_outpoints(self):
        for name, data in (("a", {"x": 10}), ("b", {"y": 5})):
            draft = self.contracts.prepare(name, self.done, data)
            self.done[name] = draft.seal(self.keys.sign)
            wrong_result = replace(draft, tx=replace(draft.tx, outputs=(draft.tx.outputs[0],
                                                                        self.contracts.data_output(123))))
            self.assertFalse(chain_verdict(wrong_result.seal(self.keys.sign), wrong_result.parents))
        join = self.contracts.prepare("route", self.done)
        self.assertTrue(chain_verdict(join.seal(self.keys.sign), join.parents))
        # A byte change outside the proof header and trailer still changes the bound txid.
        forged = replace(self.done["b"], locktime=1).serialize()
        witness = (self.done["a"].serialize(), forged)
        fake_proof = replace(join, payload=(witness, witness))
        self.assertFalse(chain_verdict(fake_proof.seal(self.keys.sign), join.parents))

    def test_shared_join_authenticates_the_reconstructed_transactions(self):
        contracts = Contracts(self.plan, self.keys.public, TASK_ID, target="both", join_witness="shared")
        deploy = Transaction((Input(bytes(32), 0),), (contracts.root,))
        done = {"deploy": deploy}
        done["split"] = contracts.prepare("split", done).seal(self.keys.sign)
        for version, name, data in ((1, "a", {"x": 10}), (2, "b", {"y": 5})):
            done[name] = contracts.prepare(name, done, data, version=version).seal(self.keys.sign)
        join = contracts.prepare("route", done, version=1)
        head_a, tail_a, head_b, tail_b, common = join.payload[0]
        self.assertEqual(head_a + common + tail_a, done["a"].serialize())
        self.assertEqual(head_b + common + tail_b, done["b"].serialize())
        self.assertTrue(chain_verdict(join.seal(self.keys.sign), join.parents))
        forged = (head_a, tail_a, head_b, tail_b, bytes([common[0] ^ 1]) + common[1:])
        fake = replace(join, payload=(forged, forged))
        self.assertFalse(chain_verdict(fake.seal(self.keys.sign), join.parents))

    def test_cost_explanation_applies_constraints_before_candidate_comparison(self):
        options = {"mode": "auto", "available_data": None, "available_authorizers": None, "target": "both"}
        _, report = compile_candidates(self.plan.program, self.keys.public, TASK_ID, **options)
        self.assertEqual(report["selected"], "fused")
        self.assertLess(report["candidates"]["fused"]["cost"]["whole_path_bytes"],
                        report["candidates"]["split"]["cost"]["whole_path_bytes"])
        constrained = parse(SOURCE + "\nindependent-submit a\n")
        _, report = compile_candidates(constrained, self.keys.public, TASK_ID, **options)
        self.assertEqual(report["selected"], "split")
        self.assertIn("independent-submit a", report["candidates"]["fused"]["reason"])

    def test_exact_version(self):
        cases = (("forkid-v1", 1, 5, 2), ("chronicle-v2", 2, 2, 1))
        self.assertEqual(self.contracts.version, 2)
        for target, version, activation, wrong_version in cases:
            with self.subTest(target=target):
                contracts = Contracts(self.plan, self.keys.public, TASK_ID, target=target)
                deploy = Transaction((Input(bytes(32), 0),), (contracts.root,), version=version)
                split = contracts.prepare("split", {"deploy": deploy}).seal(self.keys.sign)
                a = contracts.prepare("a", {"split": split}, {"x": 10})
                self.assertEqual(a.tx.version, version)
                self.assertEqual(a.signing_requests()[0].sighash, 0x41)
                context = dict(spend_height=4, activation_height=activation, utxo_heights=(3,))
                validate_at_heights(a.seal(self.keys.sign), a.parents, **context)
                changed = replace(a, tx=replace(a.tx, version=wrong_version))
                with self.assertRaisesRegex(ValueError, "OP_EQUALVERIFY"):
                    validate_at_heights(changed.seal(self.keys.sign), changed.parents, **context)

    def test_one_deployment_accepts_both_versions_in_any_join_position(self):
        contracts = Contracts(self.plan, self.keys.public, TASK_ID, target="both")
        deploy = Transaction((Input(bytes(32), 0),), (contracts.root,), version=2)
        split = contracts.prepare("split", {"deploy": deploy}, version=1)
        self.assertTrue(chain_verdict(split.seal(self.keys.sign), split.parents))
        done = {"deploy": deploy, "split": split.seal(self.keys.sign)}
        results = {step: {} for step in ("a", "b")}
        for version, (step, data) in product((1, 2), (("a", {"x": 10}), ("b", {"y": 5}))):
            branch = contracts.prepare(step, done, data, version=version)
            results[step][version] = branch.seal(self.keys.sign)
            self.assertTrue(chain_verdict(results[step][version], branch.parents))
        for a, b, joined in product((1, 2), repeat=3):
            with self.subTest(a=a, b=b, join=joined):
                join = contracts.prepare("route", {"a": results["a"][a], "b": results["b"][b]}, version=joined)
                self.assertTrue(chain_verdict(join.seal(self.keys.sign), join.parents))
        with self.assertRaisesRegex(ValueError, "unavailable for target both"):
            contracts.prepare("split", {"deploy": deploy}, version=3)
        with self.assertRaisesRegex(ValueError, "unavailable for target chronicle-v2"):
            self.contracts.prepare("split", self.done, version=1)

if __name__ == "__main__":
    unittest.main()

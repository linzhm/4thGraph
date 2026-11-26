"""Regression tests for Forth lowering and the transaction binding invariants."""

from dataclasses import replace
import unittest

from shared.benchmark_validation import chain_verdict
from shared.evaluate import evaluate as evaluate_script
from shared.script import decode_num, encode_num
from shared.transaction import Input, Transaction

from compiler import CompileError, U32, evaluate, lower, parse, schedule
from protocol import Contracts, invalidated
from replay import EXAMPLE, TASK_ID, TestKeys

SOURCE = EXAMPLE.read_text()


class CompilerTests(unittest.TestCase):
    def test_stack_types_and_host_location(self):
        with self.assertRaisesRegex(CompileError, "declared"):
            parse(SOURCE.replace("dup u32+", "dup"))
        with self.assertRaisesRegex(CompileError, "equal branch stack types"):
            parse(SOURCE.replace("else settle", "else 1"))
        source = ": find ( outpoint -- utxo ) lookup-utxo ;\n" + SOURCE
        program = parse(source)
        self.assertEqual(program.words["find"].location, "host")
        with self.assertRaises(CompileError):
            lower(program.words["find"])

    def test_arithmetic_and_literal_lowering(self):
        source = ": wrap ( -- u32 ) 4294967295 1 u32+ ;\n" + SOURCE
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

    def test_schedule_constraints(self):
        program = parse(SOURCE)
        self.assertEqual(schedule(program).mode, "fused")
        plan = schedule(program, available_data=("x",), available_authorizers=("alice",))
        self.assertEqual(plan.mode, "split")
        self.assertIn("b: input y is unavailable at fusion", plan.fusion_blockers)
        self.assertIn("b: authorizer bob is unavailable at fusion", plan.fusion_blockers)
        constrained = parse(SOURCE + "\na independent-submit\n")
        self.assertEqual(schedule(constrained).mode, "split")
        with self.assertRaisesRegex(CompileError, "line 11: a independent-submit"):
            schedule(constrained, "fused")


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

    def test_exact_version(self):
        a = self.contracts.prepare("a", self.done, {"x": 10})
        v1 = replace(a, tx=replace(a.tx, version=1))
        self.assertFalse(chain_verdict(v1.seal(self.keys.sign), v1.parents))


if __name__ == "__main__":
    unittest.main()

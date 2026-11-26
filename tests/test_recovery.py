"""Check refund authorization, mutual input binding, and state reporting."""

from dataclasses import replace
import unittest

from fourthgraph.compiler.source import CompileError, parse, schedule
from fourthgraph.workflow.protocol import Contracts, REFUND_FEE, REFUND_SEQUENCE
from fourthgraph.replay.workflow import EXAMPLE, GATED_EXAMPLE, TASK_ID, TestKeys
from fourthgraph.benchmark.validation import chain_verdict
from fourthgraph.bsv.transaction import Input, Transaction


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = TestKeys()

    def contract(self, source, mode, witness):
        program = parse(source + "\nrecovery: 145 review\n")
        return Contracts(schedule(program, mode), self.keys.public, TASK_ID, target="both", join_witness=witness)

    def test_height_is_a_block_height_and_the_role_must_have_a_key(self):
        for height in ("0", "500000000", "-1", "0xFF"):
            with self.subTest(height=height), self.assertRaisesRegex(CompileError, "recovery height"):
                parse(EXAMPLE.read_text() + f"\nrecovery: {height} review\n")
        plan = schedule(parse(EXAMPLE.read_text() + "\nrecovery: 145 trustee\n"))
        with self.assertRaisesRegex(ValueError, "trustee requires"):
            Contracts(plan, self.keys.public, TASK_ID)

    def test_each_intermediate_output_has_a_bound_timeout_spend(self):
        variants = (
            (EXAMPLE.read_text(), "split", {"x": 10, "y": 5}),
            (EXAMPLE.read_text(), "fused", {"x": 10, "y": 5}),
            (GATED_EXAMPLE.read_text().replace("qualify z", "qualify x") + "\nindependent-submit qualify",
             "split", {"x": 2, "y": 20}),
        )
        for source, mode, data in variants:
            for witness in ("full", "shared"):
                with self.subTest(mode=mode, witness=witness, gate="gate:" in source):
                    c = self.contract(source, mode, witness)
                    done = {"deploy": Transaction((Input(bytes(32), 0),), (c.root,))}
                    for index, step in enumerate(c.plan.templates):
                        draft = c.prepare(step.name, done, data, version=1 + index % 2)
                        done[step.name] = draft.seal(self.keys.sign)
                        self.assertTrue(chain_verdict(done[step.name], draft.parents))
                    for ref in c.recovery_refs():
                        draft = c.prepare_refund(ref.step, done, vout=ref.vout, version=1)
                        self.assertEqual(draft.tx.locktime, 145)
                        self.assertEqual(draft.tx.inputs[0].sequence, REFUND_SEQUENCE)
                        self.assertEqual(draft.tx.outputs[0].value, draft.previous[0].output.value - REFUND_FEE)
                        self.assertEqual(draft.signing_requests()[0].authorizer, "review")
                        self.assertTrue(chain_verdict(draft.seal(self.keys.sign), draft.parents))
                        early = replace(draft, tx=replace(draft.tx, locktime=144))
                        self.assertFalse(chain_verdict(early.seal(self.keys.sign), early.parents))
                    with self.assertRaisesRegex(ValueError, "has no recovery path"):
                        c.prepare_refund(c.plan.templates[-1].name, done)

    def test_state_exposes_the_other_worker_and_disables_spent_outputs(self):
        c = self.contract(EXAMPLE.read_text(), "split", "shared")
        done = {"deploy": Transaction((Input(bytes(32), 0),), (c.root,))}
        for step in ("split", "a"):
            done[step] = c.prepare(step, done, {"x": 10}).seal(self.keys.sign)
        work = c.prepare_refund("split", done, vout=1).previous[0].outpoint
        result = c.prepare_refund("a", done).previous[0].outpoint
        before = c.recovery_status(done, (work, result), tip_height=144)
        self.assertEqual([row["step"] for row in before["advance"]], ["b"])
        self.assertEqual([row["height_reached"] for row in before["refund"]], [False, False])
        after = c.recovery_status(done, (work,), tip_height=145)
        self.assertEqual([row["outpoint"] for row in after["refund"]], [work.text()])
        self.assertTrue(after["refund"][0]["height_reached"])
        self.assertEqual(after["refund"][0]["refund_satoshis"], 506_500)


if __name__ == "__main__":
    unittest.main()

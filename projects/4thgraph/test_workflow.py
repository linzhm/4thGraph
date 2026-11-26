"""Typed stage dependencies, compiled artifacts and parent binding."""

from dataclasses import replace
from hashlib import sha256
import unittest

from compiler import WORKFLOW_MODES, CompileError, ParentOutput, SourceCompiler
from forkid_lowering import LINKED_CONTEXT_BYTES, OTDA_ALL, LinkedContext
from protocol import BINDING_CODE, FLAG, artifact_digest, invalidated
from replay import TestKeys
from shared.chain_gang import validate_at_heights
from shared.evaluate import evaluate as evaluate_script
from shared.script import asm
from shared.transaction import Input, Output, Transaction, preimage_forkid, preimage_otda
from workflow_contract import WorkflowContracts, compile_workflow
from workflow_replay import SOURCE


class WorkflowTests(unittest.TestCase):
    def test_linked_context_rebuilds_the_exact_forkid_preimage(self):
        program = SourceCompiler(SOURCE.read_text()).workflow()
        contract = WorkflowContracts(program, TestKeys().public, 19, target="both")
        template, = contract.plan.templates
        context = LinkedContext.for_template(template, FLAG, BINDING_CODE, ("terminal", "receipt"))
        script = asm("OP_SWAP OP_TOALTSTACK") + context.bind_outputs() + asm("OP_FROMALTSTACK")
        for version, sequence, locktime in ((1, 0xFFFFFFFE, 87), (2, 0xFFFFFFFF, 0)):
            tx = Transaction((Input(bytes(range(32)), 257, sequence=sequence),),
                             (Output(1000, b"\x51"), Output(0, b"\x00\x6a")),
                             version=version, locktime=locktime)
            full = preimage_forkid(tx, 0, 1001, BINDING_CODE, FLAG)
            packed = context.pack(full)
            self.assertEqual(len(packed), LINKED_CONTEXT_BYTES)
            outputs = b"".join(output.serialize() for output in tx.outputs)
            self.assertEqual(evaluate_script(script, [b"sentinel", packed, outputs]),
                             ([b"sentinel", full], []))
        self.assertIsNone(LinkedContext.for_template(template, FLAG, BINDING_CODE, ("terminal",)))
        self.assertIsNone(LinkedContext.for_template(template, FLAG, BINDING_CODE, ("receipt", "terminal")))
        self.assertIsNone(LinkedContext.for_template(template, 0x43, BINDING_CODE, template.outputs))
        self.assertIsNone(LinkedContext.for_template(template, OTDA_ALL, BINDING_CODE, template.outputs))
        atomic = WorkflowContracts(program, TestKeys().public, 19, mode="atomic")
        self.assertIsNone(LinkedContext.for_template(atomic.plan.templates[0], FLAG, BINDING_CODE, template.outputs))

    def test_chronicle_context_rebuilds_and_authenticates_the_same_output_assertions(self):
        source = SOURCE.read_bytes()
        program = SourceCompiler(source.decode()).workflow()
        keys = TestKeys()
        artifact, report = compile_workflow(program, keys.public, 19, source_bytes=source, search=True,
                                            target="both", sighash_family="chronicle")
        self.assertEqual(artifact["sighash"], "61")
        self.assertEqual(artifact["era"], "chronicle")
        self.assertEqual(report["candidates"]["atomic"]["exclusions"][0]["code"], "unsupported_sighash_context")
        contract = WorkflowContracts(program, keys.public, 19, target="both", sighash_family="chronicle")
        root = Transaction((Input(bytes(32), 0),), (contract.root,))
        for version in (1, 2):
            draft = contract.prepare("fused", {"deploy": root}, version=version)
            context = contract.contexts["fused"]
            full = preimage_otda(draft.tx, 0, BINDING_CODE, OTDA_ALL)
            packed = context.pack(full)
            script = asm("OP_SWAP OP_TOALTSTACK") + context.bind_outputs() + asm("OP_FROMALTSTACK")
            outputs = b"".join(output.serialize() for output in draft.tx.outputs)
            self.assertEqual(len(packed), 48)
            self.assertEqual(evaluate_script(script, [packed, outputs]), ([full], []))
            spend = draft.seal(keys.sign)
            validate_at_heights(spend, (root,), spend_height=4, activation_height=2, utxo_heights=(3,))
            with self.assertRaises((RuntimeError, ValueError)):
                validate_at_heights(spend, (root,), spend_height=4, activation_height=10, utxo_heights=(3,))

    def test_dependency_diagnostics_point_to_the_consumer(self):
        source = SOURCE.read_text()
        cases = (
            (source.replace("decide decide next", "decide decide absent"), "no producer for 'absent'"),
            (source.replace("decide decide next", "decide decide route"), "needs u32, found route"),
            (source.replace("advance current next", "advance other next")
             .replace("decide decide next route", "decide advance next other"), "dependency cycle at 'other'"),
        )
        for candidate, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(CompileError, rf"line \d+, column \d+: .*{message}"):
                SourceCompiler(candidate).workflow()

    def test_ordered_plan_and_artifacts(self):
        source = SOURCE.read_bytes()
        *body, first, second = source.decode().splitlines()
        reordered = "\n".join((*body, second, first))
        program = SourceCompiler(reordered).workflow()
        self.assertEqual(tuple(stage.name for stage in program.stages), ("advance", "decide"))
        keys = TestKeys().public
        for mode in WORKFLOW_MODES:
            with self.subTest(mode=mode):
                contracts = WorkflowContracts(program, keys, 19, mode=mode)
                artifact = contracts.artifact(reordered.encode())
                self.assertEqual(artifact["artifact_sha256"], artifact_digest(artifact))
                self.assertEqual(artifact["source_sha256"], sha256(reordered.encode()).hexdigest())
                dependency, = artifact["dependencies"]
                self.assertEqual((dependency["producer"], dependency["consumer"], dependency["value"]),
                                 ("advance", "decide", "next"))
                self.assertEqual(dependency["source"]["line"], len(body) + 1)
                templates = artifact["templates"]
                self.assertEqual(len(templates), 2 if mode == "serial" else 1)
                expected = ({"step": "advance" if mode == "serial" else "deploy", "vout": 0},)
                if mode == "atomic":
                    expected += ({"step": "deploy", "vout": 1},)
                self.assertEqual(templates[-1]["inputs"], expected)

    def test_state_and_signing_digest_bind_actual_parent_bytes(self):
        workflow = SourceCompiler(SOURCE.read_text()).workflow()
        keys = TestKeys()
        contracts = WorkflowContracts(workflow, keys.public, 19, mode="serial", target="both")
        root = Transaction((Input(bytes(32), 0),), (contracts.root,))
        other = replace(root, locktime=1)
        own_draft = contracts.prepare("advance", {"deploy": root}, version=1)
        own = own_draft.seal(keys.sign)
        foreign = contracts.prepare("advance", {"deploy": other}).seal(keys.sign)
        with self.assertRaisesRegex(ValueError, "different workflow root"):
            contracts.prepare("decide", {"deploy": root, "advance": foreign})
        changed = replace(own_draft, tx=replace(own_draft.tx, locktime=1)).seal(keys.sign)
        before, after = (contracts.prepare("decide", {"deploy": root, "advance": tx}).signing_requests()[0]
                         for tx in (own, changed))
        self.assertEqual(before.outpoint.txid, own.txid_wire())
        self.assertEqual(after.outpoint.txid, changed.txid_wire())
        self.assertNotEqual(before.digest, after.digest)
        self.assertEqual(before.witness_data, (own.serialize(),))
        self.assertEqual(after.witness_data, (changed.serialize(),))
        self.assertEqual(invalidated(contracts.plan, "advance", own, changed), {"decide": ("bob",)})
        self.assertEqual(invalidated(contracts.plan, "deploy", root, other),
                         {"advance": ("operator",), "decide": ("bob",)})

    def test_search_filters_authority_and_boundary_before_ranking(self):
        source = SOURCE.read_bytes()
        keys = TestKeys().public

        def compile_example(raw=source, **options):
            return compile_workflow(SourceCompiler(raw.decode()).workflow(), keys, 19,
                                    source_bytes=raw, search=True, **options)

        artifact, default = compile_example()
        self.assertEqual(compile_example(), (artifact, default))
        self.assertEqual(default["selected"], "fused")
        for layout in ("fused", "serial"):
            layouts = default["candidates"][layout]["preimage_candidates"]
            self.assertTrue(layouts["reconstructed"]["selected"])
            self.assertLess(layouts["reconstructed"]["cost"]["whole_path_bytes"],
                            layouts["full"]["cost"]["whole_path_bytes"])
        self.assertEqual(tuple(default["candidates"]["atomic"]["preimage_candidates"]), ("full",))
        self.assertEqual({name for name, row in default["candidates"].items() if row["eligible"]},
                         set(WORKFLOW_MODES))
        self.assertEqual(artifact["artifact_sha256"], default["candidates"]["fused"]["artifact_sha256"])
        _, peak = compile_example(objective="peak-validation")
        self.assertEqual(peak["selected"], "serial")
        cap = default["candidates"]["fused"]["cost"]["max_transaction_bytes"]
        _, budget = compile_example(objective="peak-validation", max_tx_bytes=cap)
        self.assertEqual(budget["selected"], "fused")
        self.assertEqual(budget["candidates"]["serial"]["exclusions"][0]["code"], "transaction_byte_budget")
        with self.assertRaisesRegex(CompileError, "no requested workflow layout"):
            compile_example(max_tx_bytes=cap - 1)
        _, late = compile_example(available_authorizers=("operator",))
        self.assertEqual(late["selected"], "serial")
        self.assertEqual(late["candidates"]["atomic"]["exclusions"][0]["role"], "bob")
        with self.assertRaisesRegex(CompileError, "operator must be available"):
            compile_example(available_authorizers=("bob",))

        for step in ("advance", "decide"):
            with self.subTest(step=step):
                extra = source + f"independent-submit {step}\n".encode()
                _, separate = compile_example(extra)
                self.assertEqual(separate["selected"], "serial")
                for mode in ("fused", "atomic"):
                    exclusion, = separate["candidates"][mode]["exclusions"]
                    self.assertEqual((exclusion["code"], exclusion["stage"], exclusion["line"]),
                                     ("independent_submit", step, len(source.splitlines()) + 1))
        with self.assertRaisesRegex(CompileError, "unknown workflow stage 'missing'"):
            compile_example(source + b"independent-submit missing\n")

    def test_atomic_signing_requests_bind_distinct_inputs_and_deployment(self):
        source = SOURCE.read_bytes()
        stages = SourceCompiler(source.decode()).workflow()
        keys = TestKeys()
        contract = WorkflowContracts(stages, keys.public, 19, mode="atomic", target="both")
        root = Transaction((Input(bytes(32), 0),), contract.deployment_outputs)
        done = {"deploy": root}
        draft = contract.prepare("atomic", done)
        first, second = draft.signing_requests()
        self.assertEqual((first.input_index, first.authorizer, first.outpoint.vout), (0, "operator", 0))
        self.assertEqual((second.input_index, second.authorizer, second.outpoint.vout), (1, "bob", 1))
        self.assertEqual(first.outpoint.txid, second.outpoint.txid)
        self.assertNotEqual(first.digest, second.digest)
        with self.assertRaisesRegex(ValueError, "authorization does not match"):
            replace(draft, input_authorizers=(("bob",), ("operator",))).signing_requests()
        changed = replace(root, outputs=(root.outputs[0], replace(root.outputs[1], script=b"")))
        with self.assertRaisesRegex(ValueError, "mismatched workflow deployment"):
            contract.prepare("atomic", {"deploy": changed})
        with self.assertRaisesRegex(ValueError, "distinct stage signers"):
            WorkflowContracts(stages, {**keys.public, "bob": keys.public["operator"]}, 19)
        shared = replace(stages, stages=(stages.stages[0], replace(stages.stages[1], owner="operator")))
        for mode, count in (("atomic", 2), ("fused", 1)):
            with self.subTest(mode=mode):
                contract = WorkflowContracts(shared, keys.public, 19, mode=mode)
                root = Transaction(root.inputs, contract.deployment_outputs)
                requests = contract.prepare(mode, {"deploy": root}).signing_requests()
                self.assertEqual([request.authorizer for request in requests], ["operator"] * count)
                self.assertEqual([request.input_index for request in requests], list(range(count)))

    def test_recovery_reports_remaining_atomic_output(self):
        source = SOURCE.read_text() + "\nrecovery: 145 review\n"
        stages = SourceCompiler(source).workflow()
        keys = TestKeys()
        contract = WorkflowContracts(stages, keys.public, 19, mode="atomic")
        root = Transaction((Input(bytes(32), 0),), contract.deployment_outputs)
        done = {"deploy": root}
        draft = contract.prepare("atomic", done)
        _, sibling = draft.previous
        for height, eligible in ((144, False), (145, True)):
            status = contract.recovery_status(done, (sibling.outpoint,), tip_height=height)
            self.assertFalse(status["advance"])
            refund, = status["refund"]
            self.assertEqual(refund["eligible_next_block"], eligible)
            self.assertEqual(refund["output"]["satoshis"], 9000)
            self.assertEqual(refund["authorizer"], "review")
        with self.assertRaisesRegex(ValueError, "no recovery branch"):
            contract.prepare_refund(ParentOutput("deploy", 2), done)


if __name__ == "__main__":
    unittest.main()

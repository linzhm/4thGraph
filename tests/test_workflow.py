"""Typed stage dependencies, compiled artifacts and parent binding."""

from contextlib import redirect_stdout
from dataclasses import replace
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fourthgraph.compiler.source import WORKFLOW_MODES, CompileError, ParentOutput, SourceCompiler
from fourthgraph.workflow.forkid_lowering import LINKED_CONTEXT_BYTES, OTDA_ALL, LinkedContext
from fourthgraph.workflow.protocol import BINDING_CODE, FLAG, artifact_digest, invalidated, main
from fourthgraph.replay.workflow import TestKeys
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.evaluate import evaluate as evaluate_script
from fourthgraph.bsv.script import asm
from fourthgraph.bsv.transaction import Input, Output, Transaction, preimage_forkid, preimage_otda
from fourthgraph.workflow.workflow_contract import WorkflowContracts, compile_workflow
from fourthgraph.replay.typed_workflow import SOURCE


class WorkflowTests(unittest.TestCase):
    def test_linked_context_preserves_output_vector_serialization(self):
        script_code = b"\x51"
        for flag, packed_size in ((FLAG, LINKED_CONTEXT_BYTES), (OTDA_ALL, LINKED_CONTEXT_BYTES - 8)):
            for output_count in (1, 2, 16, 17, 252, 253):
                labels = tuple(range(output_count))
                template = SimpleNamespace(inputs=("state",), outputs=labels)
                context = LinkedContext.for_template(template, flag, script_code, labels,
                                                     requires_previous_amount=False)
                script = asm("OP_SWAP OP_TOALTSTACK") + context.bind_outputs() + asm("OP_FROMALTSTACK")
                outputs = tuple(Output(index, script_code) for index in labels)
                serialized = b"".join(output.serialize() for output in outputs)
                for version, sequence, locktime in ((1, 0xFFFFFFFE, 87), (2, 0xFFFFFFFF, 0)):
                    with self.subTest(flag=hex(flag), output_count=output_count, version=version):
                        tx = Transaction((Input(bytes(range(32)), 257, sequence=sequence),),
                                         outputs, version=version, locktime=locktime)
                        expected = (preimage_forkid(tx, 0, 1001, script_code, flag) if flag == FLAG
                                    else preimage_otda(tx, 0, script_code, flag))
                        packed = context.pack(expected)
                        self.assertEqual(len(packed), packed_size)
                        self.assertEqual(evaluate_script(script, [b"sentinel", packed, serialized]),
                                         ([b"sentinel", expected], []))

    def test_cli_aliases_emit_identical_canonical_artifacts(self):
        keys = TestKeys().public
        with TemporaryDirectory() as scratch:
            path = Path(scratch) / "keys.json"
            path.write_text(json.dumps({name: key.hex() for name, key in keys.items()}))
            base = ["4thgraph", str(SOURCE), "--keys", str(path), "--current", "19", "--mode", "fused"]
            for canonical, legacy, target, flag in (
                (["--target", "bip143-v1", "--sighash-family", "bip143"],
                 ["--target", "forkid-v1", "--sighash-family", "forkid"], "bip143-v1", "41"),
                (["--sighash-family", "otda"], ["--sighash-family", "chronicle"], "chronicle-v2", "61"),
            ):
                builds = []
                for options in (canonical, legacy):
                    with patch("sys.argv", base + options), redirect_stdout(StringIO()) as output:
                        main()
                    builds.append(json.loads(output.getvalue()))
                self.assertEqual(builds[0], builds[1])
                self.assertEqual(builds[0]["target"], target)
                self.assertEqual(builds[0]["sighash"], flag)

    def test_linked_context_rebuilds_the_exact_forkid_preimage(self):
        program = SourceCompiler(SOURCE.read_text(), source_path=SOURCE).workflow()
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
        program = SourceCompiler(source.decode(), source_path=SOURCE).workflow()
        keys = TestKeys()
        artifact, report = compile_workflow(program, keys.public, 19, source_bytes=source, search=True,
                                            target="both", sighash_family="otda")
        self.assertEqual(artifact["sighash"], "61")
        self.assertEqual(artifact["era"], "chronicle")
        self.assertEqual(report["candidates"]["atomic"]["exclusions"][0]["code"], "unsupported_sighash_context")
        contract = WorkflowContracts(program, keys.public, 19, target="both", sighash_family="otda")
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

    def test_dual_lock_binds_authorizations_to_the_selected_preimage(self):
        source = SOURCE.read_bytes()
        program = SourceCompiler(source.decode(), source_path=SOURCE).workflow()
        keys = TestKeys()
        options = dict(target="both", sighash_family="both")
        contract = WorkflowContracts(program, keys.public, 19, mode="fused", **options)
        artifact, report = compile_workflow(program, keys.public, 19, source_bytes=source, search=True, **options)
        self.assertEqual(artifact, contract.artifact(source))
        self.assertEqual(artifact["sighash_families"], {
            "bip143": {"flag": "41", "packed_context_bytes": 56},
            "otda": {"flag": "61", "packed_context_bytes": 48},
        })
        self.assertEqual(report["candidates"]["atomic"]["exclusions"][0]["code"], "unsupported_sighash_context")
        with self.assertRaisesRegex(CompileError, "requires a Chronicle spend target"):
            WorkflowContracts(program, keys.public, 19, target="forkid-v1", sighash_family="both")
        with self.assertRaisesRegex(CompileError, "recovery branch is unavailable"):
            with_recovery = SourceCompiler(source.decode() + "\nrecovery: 145 review ;\n", source_path=SOURCE).workflow()
            WorkflowContracts(with_recovery, keys.public, 19, **options)
        root = Transaction((Input(bytes(32), 0),), contract.deployment_outputs)
        done = {"deploy": root}
        self.assertEqual(contract.prepare("fused", done).sighash, FLAG)
        with self.assertRaisesRegex(ValueError, "unavailable for this spend"):
            contract.prepare("fused", done, sighash_family="both")

        def validate(spend, activation=10):
            validate_at_heights(spend, (root,), spend_height=12, activation_height=activation, utxo_heights=(5,))

        for version in (1, 2):
            forkid, chronicle = (contract.prepare("fused", done, version=version, sighash_family=family)
                                 for family in ("forkid", "chronicle"))
            self.assertEqual(forkid.tx, chronicle.tx)
            self.assertEqual(tuple(item.sighash for item in forkid.signing_requests()), (FLAG, FLAG))
            self.assertEqual(tuple(item.sighash for item in chronicle.signing_requests()), (OTDA_ALL, OTDA_ALL))
            validate(forkid.seal(keys.sign))
            validate(chronicle.seal(keys.sign))
            validate(forkid.seal(keys.sign), activation=20)
            with self.assertRaises((RuntimeError, ValueError)):
                validate(chronicle.seal(keys.sign), activation=20)
            for draft, other in ((forkid, chronicle), (chronicle, forkid)):
                with self.subTest(version=version, sighash=draft.sighash):
                    alternate = other.context_encoder(other.preimage(0, BINDING_CODE))
                    crossed = replace(draft, context_encoder=lambda _: alternate)
                    malformed = replace(draft, context_encoder=lambda data: draft.context_encoder(data) + b"\0")
                    reordered = replace(draft, tx=replace(draft.tx, outputs=draft.tx.outputs[::-1]))
                    for rejected in (crossed, malformed, reordered):
                        with self.assertRaises((RuntimeError, ValueError)):
                            validate(rejected.seal(keys.sign))

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
                SourceCompiler(candidate, source_path=SOURCE).workflow()

    def test_ordered_plan_and_artifacts(self):
        source = SOURCE.read_bytes()
        *body, first, second = source.decode().splitlines()
        reordered = "\n".join((*body, second, first))
        program = SourceCompiler(reordered, source_path=SOURCE).workflow()
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
        workflow = SourceCompiler(SOURCE.read_text(), source_path=SOURCE).workflow()
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
            return compile_workflow(SourceCompiler(raw.decode(), source_path=SOURCE).workflow(), keys, 19,
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
        stages = SourceCompiler(source.decode(), source_path=SOURCE).workflow()
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
        stages = SourceCompiler(source, source_path=SOURCE).workflow()
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

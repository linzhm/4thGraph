"""Exercise a dynamic PELS successor rule with no payment-project imports."""

from dataclasses import replace
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.script import push
from fourthgraph.bsv.transaction import Input, Output, Transaction, preimage_forkid
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.source import CompileError
from fourthgraph.stdlib import capabilities
from fourthgraph.workflow.pels import assemble_pels, compile_successor
from fourthgraph.workflow.protocol import FLAG, build_artifact


SOURCE = """
REQUIRE stdlib/wallet/pels-verify.fth

: draft-tag ( -- bytes ) bytes-hex 0300000000 ;
: ready-tag ( -- bytes ) bytes-hex 0900000000 ;

: next-status ( script -- script )
    op-dup draft-tag bsv-push op-equal op-if
        op-drop ready-tag bsv-push
    op-else
        ready-tag bsv-push op-equalverify draft-tag bsv-push
    op-endif
;

: status-rule ( script -- script )
    op-8 op-num2bin op-swap next-status op-swap
;

: status-lock ( script bytes -- script )
    bsv-push op-codeseparator
    bsv-empty status-rule pels-verify op-drop op-1
;
"""
DRAFT, READY = (value.to_bytes(5, "little") for value in (3, 9))


def pinned_chain_available():
    try:
        return chain_metadata()["commit"] == CONTEXT_PIN
    except PackageNotFoundError:
        return False


class PelsSuccessorLibraryTests(unittest.TestCase):
    def setUp(self):
        self.builder = ScriptBuilder(SOURCE)

    def test_bundled_template_keeps_exact_script_and_records_imports(self):
        versions = {row.name for row in self.builder.library_imports}
        self.assertTrue({"std/wallet/pels-verify", "std/wallet/pels-binding",
                         "std/wallet/pels-successor"} <= versions)
        draft = self.builder.emit("status-lock", b"", DRAFT)
        self.assertEqual(len(draft), 645)
        self.assertEqual(sha256(draft).hexdigest(), "f2e8d422e2e6a27542590114a3ca46f564a62b1c872f778bd5f4030cca6e8e57")

    def test_catalog_records_build_and_spend_requirements(self):
        libraries = capabilities()
        for module, word, runtime in (
            ("pels-verify", "pels-verify", ["tail", "head", "state"]),
            ("pels-successor", "pels-assert-successor", ["state", "preimage"]),
        ):
            with self.subTest(word=word):
                interface = libraries[f"std/wallet/{module}"]["interfaces"][word]
                self.assertEqual([field["name"] for field in interface["runtime_inputs"]], runtime)
                build = {field["name"]: field["type"] for field in interface["build_parameters"]}
                self.assertEqual(build, {"prefix": "script", "state-amount-rule": "script"})
                context = {field["name"]: field["description"] for field in interface["transaction_context"]}
                self.assertEqual(context["sighash"], "BIP143 ALL (0x41)")
                self.assertEqual(context["input-count"], "Exactly one input")
                self.assertEqual(context["output-count"], "Exactly one successor output")
                self.assertIn("script-code", context)

    @unittest.skipUnless(pinned_chain_available(), "requires pinned chain-gang")
    def test_non_counter_rule_follows_actual_parent_outputs(self):
        from fourthgraph.bsv.chain_gang import validate_at_heights

        lock = self.builder.emit("status-lock", b"", DRAFT)
        parent = Transaction((Input(bytes(32), 0),), (Output(10_000, lock),))
        for phase, expected in enumerate((READY, DRAFT)):
            previous = parent.outputs[0]
            successor = push(expected) + previous.script[6:]
            self.assertEqual(successor, self.builder.emit("status-lock", b"", expected))
            tx = Transaction((Input(parent.txid_wire(), 0),), (Output(previous.value, successor),))
            preimage = preimage_forkid(tx, 0, previous.value, previous.script[7:], 0x41)
            witness = push(preimage[-8:]) + push(preimage[:-40])
            signed = tx.with_script(0, witness)
            validate_at_heights(signed, (parent,), spend_height=4 + phase, activation_height=2,
                                utxo_heights=(3 + phase,))
            parent = signed


class PelsSuccessorTargetTests(unittest.TestCase):
    def test_selection_is_gated_by_authenticated_amount(self):
        source = ScriptBuilder(SOURCE)
        result = compile_successor(source, "status-rule", DRAFT, "chronicle-v2", "auto")
        self.assertEqual(result["transaction_versions"], (2,))
        self.assertEqual(result["selection"]["selected"], "bip143")
        self.assertIn("no authenticated prevout amount", result["selection"]["excluded_families"]["otda"])
        self.assertEqual(set(result["paths"]), {"bip143"})
        for family in ("otda", "both"):
            with self.subTest(family=family), self.assertRaisesRegex(CompileError, "no authenticated prevout amount"):
                compile_successor(source, "status-rule", DRAFT, "chronicle-v2", family)

    def test_linking_requires_the_bundled_export_and_fixed_state_layout(self):
        with self.assertRaisesRegex(CompileError, "bundled"):
            source = ScriptBuilder(SOURCE + "\n: pels-verify ( script script -- script ) drop ;")
            compile_successor(source, "status-rule", DRAFT, "chronicle-v2", "auto")
        with self.assertRaisesRegex(CompileError, "must contain 5 bytes"):
            compile_successor(ScriptBuilder(SOURCE), "status-rule", DRAFT[:-1], "chronicle-v2", "auto")
        with self.assertRaisesRegex(CompileError, "cannot emit OP_CODESEPARATOR"):
            source = ScriptBuilder(SOURCE + "\n: bad-rule ( script -- script ) op-codeseparator ;")
            compile_successor(source, "bad-rule", DRAFT, "chronicle-v2", "auto")

    @unittest.skipUnless(pinned_chain_available(), "requires pinned chain-gang")
    def test_cli_spends_two_actual_prevouts_and_validates_the_compiled_target(self):
        from fourthgraph.bsv.chain_gang import validate_at_heights

        command = [sys.executable, "-m", "fourthgraph.workflow.protocol"]
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source = directory / "status.fth"
            source.write_text(SOURCE)
            for target, versions, activation in (("bip143-v1", (1, 1), 10),
                                                  ("chronicle-v2", (2, 2), 2), ("both", (1, 2), 5)):
                with self.subTest(target=target):
                    def build(state):
                        path = directory / f"{state.hex()}.json"
                        path.write_bytes(subprocess.check_output(command + [
                            str(source), "--entry", "status-rule", "--pels-successor-state", state.hex(),
                            "--target", target, "--sighash-family", "auto", "--explain",
                        ]))
                        return path, json.loads(path.read_text())

                    artifacts = {state: build(state) for state in (DRAFT, READY)}
                    locks = {state: bytes.fromhex(row["script_hex"]) for state, (_, row) in artifacts.items()}
                    parent = Transaction((Input(bytes(32), 0),), (Output(10_000, locks[DRAFT]),))
                    for phase, (current, expected) in enumerate(((DRAFT, READY), (READY, DRAFT))):
                        manifest, artifact = artifacts[current]
                        prevout = parent.outputs[0]
                        tx = Transaction((Input(parent.txid_wire(), 0),),
                                         (Output(prevout.value, locks[expected]),), version=versions[phase])
                        parent_file, unsigned_file = directory / "parent.hex", directory / "unsigned.hex"
                        parent_file.write_text(parent.serialize().hex())
                        unsigned_file.write_text(tx.serialize().hex())
                        result = json.loads(subprocess.check_output(command + [
                            "pels-witness", str(manifest), "--parent", str(parent_file), "--unsigned", str(unsigned_file),
                        ]))
                        assembled = Transaction.parse(bytes.fromhex(result["transaction_hex"]))
                        self.assertEqual(result["sighash_family"], "bip143")
                        self.assertEqual(result["artifact_sha256"], artifact["artifact_sha256"])
                        self.assertEqual(assembled.with_script(0, b""), tx)
                        validate_at_heights(assembled, (parent,), spend_height=4 + phase,
                                            activation_height=activation, utxo_heights=(3 + phase,))
                        if target == "chronicle-v2" and phase == 0:
                            self.check_rejected_spends(artifact, parent, tx)
                        parent = assembled

    def check_rejected_spends(self, artifact, parent, tx):
        from fourthgraph.bsv.chain_gang import validate_at_heights

        output = tx.outputs[0]
        prevout = parent.outputs[0]
        overspend = replace(tx, outputs=(replace(output, value=prevout.value + 1),))
        with self.assertRaisesRegex(ValueError, "exceeds the actual prevout amount"):
            assemble_pels(artifact, parent, overspend)
        for bad_output in (replace(output, value=output.value - 1), replace(output, script=prevout.script)):
            with self.subTest(output=bad_output):
                wrong = replace(tx, outputs=(bad_output,))
                signed, _ = assemble_pels(artifact, parent, wrong)
                with self.assertRaises((ValueError, RuntimeError)):
                    validate_at_heights(signed, (parent,), spend_height=4, activation_height=2, utxo_heights=(3,))
        wrong_version = replace(tx, version=1)
        with self.assertRaisesRegex(ValueError, "outside the compiled target"):
            assemble_pels(artifact, parent, wrong_version)
        offset = artifact["paths"]["bip143"]["script_code_offset"]
        preimage = preimage_forkid(wrong_version, 0, prevout.value, prevout.script[offset:], FLAG)
        signed = wrong_version.with_script(0, push(preimage[-8:]) + push(preimage[:-40]))
        with self.assertRaises((ValueError, RuntimeError)):
            validate_at_heights(signed, (parent,), spend_height=4, activation_height=2, utxo_heights=(3,))

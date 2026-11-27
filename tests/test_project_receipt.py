from dataclasses import replace
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
import json
import os
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.transaction import Input, Transaction
from fourthgraph.compiler.source import SourceCompiler
from tools import verify_project_contract as verifier


ROOT = Path(__file__).resolve().parents[1]
R1 = ROOT / "projects/p2pkh-r1/versions/v0.6.0/contract"
COUNTER = ROOT / "projects/pels-counter/versions/v0.1.0/contract"


def read_bundle(directory):
    manifest = directory / "manifest.json"
    return manifest, sha256(manifest.read_bytes()).hexdigest(), json.loads((directory / "receipt.json").read_bytes())


def integration_available():
    try:
        return shutil.which("node") and chain_metadata()["commit"] == CONTEXT_PIN
    except PackageNotFoundError:
        return False


class ProjectReceiptTests(unittest.TestCase):
    @unittest.skipUnless(integration_available(), "requires pinned chain-gang and Node WASI runtime")
    def test_counter_wrap_matches_the_published_lock(self):
        manifest, approval, _ = read_bundle(COUNTER)
        host = verifier.ProjectContract(manifest, approval)
        project = ROOT / "projects/pels-counter"
        reference = run_path(str(project / "pels_counter.py"))
        source = project / "pels-counter.fth"
        advance = SourceCompiler(source.read_text(), source_path=source).words["advance"]
        code = host.template[host.package["paths"]["advance"]["script_code_offset"]:]
        parent = Transaction((Input(bytes(32), 0),), (reference["counter_output"](code, 0xffffffff, 10_000),))
        _, successor, output = reference["next_counter"](parent, code, advance)
        self.assertEqual(successor, 0)
        reference_spend = reference["spend"](parent, code, output)
        self.assertTrue(verifier.chain_verdict(reference_spend, (parent,)))
        actual = host.spend(parent, reference_spend.with_script(0, b""), 0, "advance", b"",
                            lambda *_: self.fail("counter must not request a signature"),
                            lambda tx: verifier.chain_verdict(tx, (parent,)))
        self.assertEqual(actual, reference_spend)

    @unittest.skipUnless(shutil.which("node"), "requires Node WASI runtime")
    def test_r1_abi_requires_an_explicit_prevout_amount(self):
        manifest, approval, receipt = read_bundle(R1)
        host = verifier.ProjectContract(manifest, approval)
        row = receipt["steps"][0]
        parent = Transaction.parse(bytes.fromhex(row["parent_tx"]))
        candidate = Transaction.parse(bytes.fromhex(row["raw_tx"])).with_script(0, b"")
        pubkey = bytes.fromhex(receipt["public_key"])
        request = host.request(parent, candidate, 0, "ordinary-all", pubkey)
        for change in ("missing", "null"):
            with self.subTest(change=change):
                prevout = dict(request["prevout"])
                if change == "missing":
                    del prevout["amount"]
                else:
                    prevout["amount"] = None
                result = host.call("prepare_spend", {**request, "prevout": prevout})
                self.assertEqual(result["status"], "MissingContext")
                self.assertNotIn("prepared", result)
                self.assertNotIn("unlock", result)

        zero_parent = replace(parent, outputs=(replace(parent.outputs[0], value=0),))
        zero_candidate = replace(candidate, inputs=(replace(candidate.inputs[0], txid=zero_parent.txid_wire()),),
                                 outputs=(replace(candidate.outputs[0], value=0),))
        self.assertEqual(host.prepare(zero_parent, zero_candidate, 0, "ordinary-all", pubkey)["mode"], 65)

    @unittest.skipUnless(integration_available(), "requires pinned chain-gang and Node WASI runtime")
    def test_cli_defaults_to_chain_gang_and_honors_node_opt_in(self):
        manifest, approval, _ = read_bundle(R1)
        env = os.environ.copy()
        env.pop("REGTEST_URL", None)
        env.pop("REGTEST_COOKIE", None)
        with TemporaryDirectory() as temp:
            receipt = Path(temp) / "receipt.json"
            replay = Path(temp) / "replay.json"
            command = [sys.executable, str(ROOT / "tools/verify_project_contract.py"),
                       str(manifest), "--approved-sha256", approval]
            for args, output in (([], receipt), (["--replay", str(receipt)], replay)):
                result = subprocess.run(command + args + ["--output", str(output)], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(output.read_bytes())
                self.assertEqual((report["status"], report["verification_level"]), ("passed", "chain-only"))
                self.assertIsNone(report["node_version"])
            self.assertEqual(report["steps"][0]["engines"], {"chain_gang": True, "bsv_node": "not_run"})
            result = subprocess.run(command + ["--with-bsv-node", "--replay", str(receipt), "--output", str(replay)],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            failure = json.loads(replay.read_bytes())
            self.assertEqual(failure["requested_verification_level"], "dual-engine")
            self.assertIn("REGTEST_URL", failure["diagnostic"]["detail"])

    def assert_rejected(self, status, manifest, approval, receipt, **kwargs):
        with self.assertRaises(verifier.VerificationFailure) as error:
            verifier.replay_receipt(manifest, approval, receipt, **kwargs)
        diagnostic = error.exception.report["diagnostic"]
        self.assertEqual(diagnostic["status"], status)
        return diagnostic

    def test_manifest_approval_and_receipt_bindings(self):
        manifest, approval, receipt = read_bundle(R1)
        with self.assertRaisesRegex(verifier.ContractError, "local approval"):
            verifier.replay_receipt(manifest, "0" * 64, receipt)
        for field in ("profile", "template", "path", "module_sha256", "template_sha256", "fixture_sha256"):
            with self.subTest(field=field):
                changed = {**receipt, field: "invalid"}
                diagnostic = self.assert_rejected("receipt_binding_mismatch", manifest, approval, changed)
                self.assertEqual(diagnostic["field"], field)
        self.assert_rejected("owner_mismatch", manifest, approval, receipt, public_key=b"different public key")
        with patch.object(verifier, "pinned_chain"):
            receipt["public_key"] = "04" + "00" * 64
            self.assert_rejected("owner_mismatch", manifest, approval, receipt)

    def test_incomplete_or_malformed_steps(self):
        manifest, approval, receipt = read_bundle(COUNTER)
        for steps in (None, [], receipt["steps"][:1], receipt["steps"] * 2):
            self.assert_rejected("step_count_mismatch", manifest, approval, {**receipt, "steps": steps})
        for field, value, status in (("raw_tx", None, "invalid_receipt"), ("parent_tx", "00", "invalid_transaction"),
                                     ("previous_amount", 99_999, "step_binding_mismatch"),
                                     ("prevout", "00", "step_binding_mismatch")):
            with self.subTest(field=field), patch.object(verifier, "pinned_chain"):
                first, second = receipt["steps"]
                changed = {**receipt, "steps": [{**first, field: value}, second]}
                diagnostic = self.assert_rejected(status, manifest, approval, changed)
                self.assertEqual(diagnostic["step"], 0)
                self.assertEqual(diagnostic["field"], field)

    def test_actual_candidate_amount_must_match_fixture_even_with_matching_metadata(self):
        manifest, approval, receipt = read_bundle(COUNTER)
        row = receipt["steps"][0]
        parent = Transaction.parse(bytes.fromhex(row["parent_tx"]))
        transaction = Transaction.parse(bytes.fromhex(row["raw_tx"]))
        output = transaction.outputs[0]
        modified = replace(transaction, outputs=(replace(output, value=output.value - 1),))
        row.update(verifier.spend_summary(parent, modified), raw_tx=modified.serialize().hex())
        with patch.object(verifier, "pinned_chain"):
            self.assert_rejected("candidate_mismatch", manifest, approval, receipt)

    @unittest.skipUnless(integration_available(), "requires pinned chain-gang and Node WASI runtime")
    def test_public_replay_does_not_sign_or_trust_claims(self):
        original_call = verifier.ProjectContract.call

        def public_call(host, entry, request):
            self.assertIn(entry, ("recognize", "prepare_spend"))
            return original_call(host, entry, request)

        with patch.object(verifier, "test_keys", side_effect=AssertionError("must not generate keys")), \
             patch.object(verifier.ProjectContract, "spend", side_effect=AssertionError("must not call signer")), \
             patch.object(verifier.ProjectContract, "call", new=public_call):
            for directory, count in ((R1, 1), (COUNTER, 2)):
                manifest, approval, receipt = read_bundle(directory)
                receipt.update(status="failed", node_version="bogus", cases=[], chain_gang={"commit": "bogus"})
                pubkey = bytes.fromhex(receipt["public_key"]) if directory == R1 else None
                report = verifier.replay_receipt(manifest, approval, receipt, public_key=pubkey)
                self.assertEqual(report["verification_level"], "chain-only")
                self.assertEqual(report["local_public_key_checked"], pubkey is not None)
                self.assertEqual(len(report["steps"]), count)
                self.assertTrue(all(row["engines"] == {"chain_gang": True, "bsv_node": "not_run"} for row in report["steps"]))

    @unittest.skipUnless(integration_available(), "requires pinned chain-gang and Node WASI runtime")
    def test_tampered_signature_with_recalculated_metadata_reaches_engine(self):
        manifest, approval, receipt = read_bundle(R1)
        row = receipt["steps"][0]
        parent = Transaction.parse(bytes.fromhex(row["parent_tx"]))
        transaction = Transaction.parse(bytes.fromhex(row["raw_tx"]))
        script = bytearray(transaction.inputs[0].script)
        script[-98] ^= 1  # Keep the ordinary path and candidate intact while changing the signature.
        modified = transaction.with_script(0, bytes(script))
        row.update(verifier.spend_summary(parent, modified), raw_tx=modified.serialize().hex())
        diagnostic = self.assert_rejected("engine_rejected", manifest, approval, receipt)
        self.assertEqual(diagnostic["engines"], {"chain_gang": False, "bsv_node": "not_run"})

    @unittest.skipUnless(integration_available(), "requires pinned chain-gang and Node WASI runtime")
    def test_counter_parent_must_be_actual_previous_transaction(self):
        manifest, approval, receipt = read_bundle(COUNTER)
        first, second = receipt["steps"]
        second["parent_tx"] = first["parent_tx"]
        diagnostic = self.assert_rejected("phase_mismatch", manifest, approval, receipt)
        self.assertEqual(diagnostic["step"], 1)

    @unittest.skipUnless(integration_available(), "requires pinned chain-gang and Node WASI runtime")
    def test_fixture_failure_cli_has_bounded_machine_diagnostics(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(COUNTER, root / "bundle")
            manifest, _, _ = read_bundle(root / "bundle")
            package = json.loads(manifest.read_bytes())
            fixture = manifest.parent / package["fixtures"]["file"]
            cases = json.loads(fixture.read_bytes())
            case = next(case for case in cases["cases"] if case["id"] == "assemble")
            case["expect"]["unlock"] = "00" * 4096
            raw = json.dumps(cases).encode()
            fixture.write_bytes(raw)
            package["fixtures"].update(sha256=sha256(raw).hexdigest(), bytes=len(raw))
            manifest.write_text(json.dumps(package))
            approval = sha256(manifest.read_bytes()).hexdigest()
            output = root / "failure.json"
            result = subprocess.run([sys.executable, str(ROOT / "tools/verify_project_contract.py"), str(manifest),
                                     "--approved-sha256", approval, "--smoke", "--output", str(output)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertLess(len(result.stderr), 1600)
            report = json.loads(result.stderr)
            self.assertEqual(report, json.loads(output.read_bytes()))
            self.assertEqual(report["status"], "failed")
            failure = report["diagnostic"]
            self.assertEqual((failure["case_id"], failure["entry"]), ("assemble", "assemble_unlock"))
            self.assertEqual(failure["expected"]["status"], failure["actual"]["status"])
            self.assertNotEqual(failure["expected"]["unlock"]["sha256"], failure["actual"]["unlock"]["sha256"])

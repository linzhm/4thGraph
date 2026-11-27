from dataclasses import replace
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.transaction import Transaction
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

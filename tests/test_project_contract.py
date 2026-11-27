from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from fourthgraph.bsv.artifacts import describe_script
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.workflow.project_contract import ContractError, ProjectContract


ROOT=Path(__file__).resolve().parents[1]
COUNTER=ROOT/"projects/pels-counter/versions/v0.1.0/contract"
OWNER=ROOT/"projects/p2pkh-r1/versions/v0.6.0/contract"


def approved(directory):
    manifest=directory/"manifest.json"
    return ProjectContract(manifest,sha256(manifest.read_bytes()).hexdigest())


class ProjectContractTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GO") and shutil.which("node"), "requires GO and the WASI runtime")
    def test_settlement_bundle_replays_both_paths(self):
        with TemporaryDirectory() as scratch:
            output = Path(scratch) / "settlement"
            subprocess.run([sys.executable, "tools/build_project_contract.py", "workflow-examples",
                            str(output), "--verify"], cwd=ROOT, check=True, capture_output=True)
            host = approved(output)
            saved = json.loads((output/"receipt.json").read_text())
            self.assertEqual([step["path"] for step in saved["steps"]], ["bip143", "otda"])
            self.assertEqual([step["unlock_bytes"] for step in saved["steps"]], [57, 49])
            self.assertIn("otda.before_activation", {case["id"] for case in saved["cases"]})
            receipt = output / "replay.json"
            cmd = [sys.executable, "tools/verify_project_contract.py", str(output/"manifest.json"),
                   "--approved-sha256", host.digest, "--output", str(receipt), "--replay"]
            subprocess.run(cmd + [str(output/"receipt.json")], cwd=ROOT, check=True, capture_output=True)
            self.assertTrue(all(step["engines"]["chain_gang"] for step in json.loads(receipt.read_text())["steps"]))
            saved["steps"][0]["raw_tx"] = saved["steps"][1]["raw_tx"]
            bad = output / "wrong-path.json"
            bad.write_text(json.dumps(saved))
            self.assertEqual(subprocess.run(cmd + [str(bad)], cwd=ROOT, capture_output=True).returncode, 1)

    def test_push_payload_is_not_a_signature_anchor(self):
        self.assertEqual(describe_script(bytes.fromhex("02abacabac"))["anchors"],
                         [{"offset":3,"op":"OP_CODESEPARATOR","bytes":1},{"offset":4,"op":"OP_CHECKSIG","bytes":1}])

    def test_verified_packages_record_outpoints_and_public_engine_evidence(self):
        for directory, count in ((OWNER,1),(COUNTER,2)):
            host=approved(directory)
            receipt=json.loads((directory/"receipt.json").read_text())
            self.assertEqual(receipt["manifest_sha256"],host.digest)
            self.assertEqual(len(receipt["steps"]),count)
            previous=None
            for row in receipt["steps"]:
                parent=Transaction.parse(bytes.fromhex(row["parent_tx"]))
                signed=Transaction.parse(bytes.fromhex(row["raw_tx"]))
                self.assertEqual(signed.txid(),row["txid"])
                self.assertEqual(signed.inputs[0].txid,parent.txid_wire())
                if previous:
                    self.assertEqual(parent,previous)
                previous=signed
            self.assertTrue(all(row["passed"] for row in receipt["cases"]))
            self.assertTrue(any(r["engines"]=={"bsv_node":True,"chain_gang":True} for r in receipt["cases"]))

    @unittest.skipUnless(shutil.which("node"),"requires Node for the WASI reactor")
    def test_module_rename_and_parent_binding(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            shutil.copytree(COUNTER,root,dirs_exist_ok=True)
            m=root/"manifest.json"
            data=json.loads(m.read_text())
            (root/data["module"]["file"]).rename(root/"project-wallet.wasm")
            data["module"]["file"]="project-wallet.wasm"
            m.write_text(json.dumps(data))
            with self.assertRaisesRegex(ContractError,"local approval"):
                ProjectContract(m,approved(COUNTER).digest)
            host=approved(root)
            parent=Transaction((Input(bytes(32),0),),(Output(10_000,host.template),))
            self.assertEqual(host.recognize(parent,0)["status"],"Match")
            tx=Transaction((Input(bytes(32),0),),(Output(9000,host.template),))
            with self.assertRaisesRegex(ContractError,"actual parent"):
                host.prepare(parent,tx,0,"advance")
            (root/"project-wallet.wasm").write_bytes(b"invalid")
            with self.assertRaisesRegex(ContractError,"digest mismatch"):
                approved(root)

    def test_regtest_and_smoke_are_separate_levels(self):
        owner=approved(OWNER)
        self.assertEqual(owner.package["paths"]["ordinary-all"]["mode"],65)
        cases=json.loads((OWNER/"cases.json").read_text())
        self.assertTrue(any(c["expect"]=={"status":"NotOwned","signer_calls":0} for c in cases["cases"]))

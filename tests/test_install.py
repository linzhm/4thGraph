"""Check that the installed compiler runs away from the source checkout."""

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def test_installed_commands_use_bundled_modules(self):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        with TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            prefix = workspace / "install with spaces"
            options = {"cwd": workspace, "env": environment}
            subprocess.check_output([sys.executable, str(ROOT / "tools/install.py"), "--prefix", str(prefix)],
                                    **options)
            compiler = prefix / "bin" / "4thgraph"
            report = prefix / "bin" / "4thgraph-report"
            source = workspace / "reduce.fth"
            source.write_text(
                "range: digit script-int 0 16 ;\n"
                "bsv-effect: reduce digit -- digit ;\n"
                ": reduce 16 cell>int int-rem ;\n",
                encoding="utf-8",
            )
            capabilities = json.loads(subprocess.check_output([sys.executable, "-I", str(compiler), "--capabilities"],
                                                              **options))
            self.assertEqual(capabilities["project"], "4thGraph")
            build = json.loads(subprocess.check_output(
                [sys.executable, "-I", str(compiler), str(source), "--entry", "reduce", "--optimize", "safe"], **options,
            ))
            self.assertEqual(build["entry"], "reduce")
            self.assertEqual(build["takes"], ["digit"])
            self.assertEqual(build["gives"], ["digit"])
            self.assertEqual(build["input_range_checks"], "emitted")
            self.assertEqual(build["rewrites"][0]["rule"], "integer-remainder-in-range")
            self.assertTrue(bytes.fromhex(build["script_hex"]))
            help_text = subprocess.check_output([sys.executable, "-I", str(report), "--help"], **options)
            self.assertIn(b"--output-dir", help_text)

    def test_installed_standard_library_and_verifier_build_outside_checkout(self):
        environment = {name: value for name, value in os.environ.items() if name != "PYTHONPATH"}
        with TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            options = {"cwd": workspace, "env": environment}
            subprocess.check_output([sys.executable, str(ROOT / "tools/install.py"), "--prefix", str(workspace)],
                                    **options)

            def run(command, *arguments):
                return subprocess.check_output([sys.executable, "-I", str(workspace / "bin" / command), *arguments],
                                               **options)

            source = workspace / "library.fth"
            source.write_text("REQUIRE stdlib/p256.fth\n")
            p256 = json.loads(run("4thgraph", str(source), "--entry", "p256-double"))
            fragment = json.loads(run("4thgraph", str(source), "--entry", "p256-double", "--assume-input-ranges"))
            self.assertEqual(fragment["script_bytes"], 76)
            self.assertEqual(p256["input_range_checks"], "emitted")
            self.assertEqual(fragment["input_range_checks"], "assumed")
            self.assertGreater(p256["script_bytes"], fragment["script_bytes"])
            self.assertTrue(p256["script_hex"].endswith(fragment["script_hex"]))
            self.assertEqual({library["name"] for library in p256["libraries"]}, {"std/bsv", "std/p256"})

            joint = json.loads(run("4thgraph", "curve-multiply", "--curve", "secp256k1", "--operation", "joint"))
            self.assertEqual(joint["selected"], "glv-joint-window-2")
            self.assertEqual(len(bytes.fromhex(joint["script_hex"])), joint["candidates"][0]["script_bytes"])

            catalog = json.loads(run("4thgraph", "--capabilities"))["libraries"]
            wallet_probe = """
from dataclasses import asdict
import json
import sys

sys.path.insert(0, sys.argv[1])
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.bsv.evaluate import evaluate

builder = ScriptBuilder(
    'REQUIRE stdlib/bip340.fth\\nREQUIRE stdlib/script-fragments.fth\\n'
    'REQUIRE stdlib/./secp256k1.fth\\n'
)
raw = bytes(range(32))
stack, alt = evaluate(builder.emit('script-reverse32', b''), [b'keep', raw])
print(json.dumps({
    "imports": [asdict(item) for item in builder.library_imports],
    "main": [item.hex() for item in stack],
    "alt": [item.hex() for item in alt],
}))
"""
            wallet = json.loads(subprocess.check_output(
                [sys.executable, "-I", "-c", wallet_probe, str(workspace / "bin" / "4thgraph")], **options,
            ))
            evidence = wallet["imports"]
            expected = {"std/bip340", "std/bsv", "std/script-fragments", "std/secp256k1"}
            self.assertEqual(len(evidence), len(expected))
            self.assertEqual({item["name"] for item in evidence}, expected)
            for item in evidence:
                self.assertEqual(item["interface_sha256"], catalog[item["name"]]["interface_sha256"])
            self.assertEqual(wallet["main"], [b"keep".hex(), bytes(range(31, -1, -1)).hex()])
            self.assertEqual(wallet["alt"], [])

            for module, entry in (("std/p2pk", "p2pk-lock"), ("std/p2pkh", "p2pkh-lock")):
                with self.subTest(module=module):
                    source.write_text(f"REQUIRE stdlib/{module.removeprefix('std/')}.fth\n")
                    build_upper = run("4thgraph", str(source), "--entry", entry.upper())
                    self.assertEqual(build_upper, run("4thgraph", str(source), "--entry", entry))
                    payment = json.loads(build_upper)
                    descriptor = catalog[module]
                    imports = {library["name"]: library for library in payment["libraries"]}
                    self.assertEqual(set(imports), {"std/bsv", module})
                    evidence = imports[module]
                    self.assertEqual(evidence["interface_sha256"], descriptor["interface_sha256"])
                    self.assertEqual(payment["library_export"], descriptor["interfaces"][entry])

            local = workspace / "wallet source"
            local.mkdir()
            dependency = local / "recipient.fth"
            dependency.write_text(": recipient ( -- cell ) 7 ;\n")
            application = local / "app.fth"
            application.write_text("REQUIRE recipient.fth\n: amount ( -- cell ) recipient ;\n")
            local_build = json.loads(run("4thgraph", str(application), "--entry", "amount"))
            self.assertEqual(local_build["script_hex"], "57")

            payment_source = local / "p2pkh.fth"
            payment_source.write_bytes((ROOT / "projects/p2pk-p2pkh-baseline/forth" / payment_source.name).read_bytes())
            owner_hash = "751e76e8199196d454941c45d1b3a323f1433bd6"
            payment = json.loads(run("4thgraph", str(payment_source), "--entry", "p2pkh",
                                     "--bind-bytes", f"owner-hash={owner_hash}"))
            self.assertEqual(payment["script_hex"], f"76a914{owner_hash}88ac")
            self.assertEqual([library["name"] for library in payment["libraries"]],
                             ["std/bsv", "std/native-p2pkh"])
            self.assertEqual(local_build["libraries"][0]["name"], "recipient.fth")

            source = workspace / "proof-counter" / "verify-state.fth"
            source.parent.mkdir()
            source.write_bytes((ROOT / "projects/proof-counter" / source.name).read_bytes())
            rules = source.with_name("counter.fth")
            rules.write_bytes((ROOT / "projects/proof-counter" / rules.name).read_bytes())
            circom = workspace / "statement.circom"
            run("4thgraph-circuit", str(source), "--output", str(circom))
            keys = workspace / "keys.json"
            x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            keys.write_text(json.dumps({"review": "02" + x, "settle": "03" + x}))
            build = json.loads(run("4thgraph-verify", str(source), "--keys", str(keys), "--current", "19"))
            self.assertEqual(build["selected"], "script")
            self.assertEqual(build["compilations"]["circuit"]["source"], circom.read_text())

"""Check that the installed compiler runs away from the source checkout."""

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


PROJECT = Path(__file__).resolve().parent


class InstallTests(unittest.TestCase):
    def test_installed_commands_use_bundled_modules(self):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        with TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            prefix = workspace / "install with spaces"
            options = {"cwd": workspace, "env": environment}
            subprocess.check_output([sys.executable, str(PROJECT / "install.py"), "--prefix", str(prefix)],
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
            subprocess.check_output([sys.executable, str(PROJECT / "install.py"), "--prefix", str(workspace)],
                                    **options)

            def run(command, *arguments):
                return subprocess.check_output([sys.executable, "-I", str(workspace / "bin" / command), *arguments],
                                               **options)

            source = workspace / "library.fth"
            source.write_text("REQUIRE stdlib/p256.fth\n")
            p256 = json.loads(run("4thgraph", str(source), "--entry", "p256-double"))
            self.assertEqual(p256["script_bytes"], 76)
            self.assertEqual(p256["libraries"][0]["name"], "std/p256")

            catalog = json.loads(run("4thgraph", "--capabilities"))["libraries"]
            for module, entry in (("std/p2pk", "p2pk-lock"), ("std/p2pkh", "p2pkh-lock")):
                with self.subTest(module=module):
                    source.write_text(f"REQUIRE stdlib/{module.removeprefix('std/')}.fth\n")
                    build_upper = run("4thgraph", str(source), "--entry", entry.upper())
                    self.assertEqual(build_upper, run("4thgraph", str(source), "--entry", entry))
                    payment = json.loads(build_upper)
                    descriptor = catalog[module]
                    evidence, = payment["libraries"]
                    self.assertEqual(evidence["name"], module)
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
            self.assertEqual(local_build["libraries"][0]["name"], "recipient.fth")

            source = workspace / "examples" / "verify-state.fth"
            source.parent.mkdir()
            source.write_bytes((PROJECT / "examples" / source.name).read_bytes())
            rules = workspace / "proof" / "counter.fth"
            rules.parent.mkdir()
            rules.write_bytes((PROJECT / "proof" / rules.name).read_bytes())
            circom = workspace / "statement.circom"
            run("4thgraph-circuit", str(source), "--output", str(circom))
            keys = workspace / "keys.json"
            x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            keys.write_text(json.dumps({"review": "02" + x, "settle": "03" + x}))
            build = json.loads(run("4thgraph-verify", str(source), "--keys", str(keys), "--current", "19"))
            self.assertEqual(build["selected"], "script")
            self.assertEqual(build["compilations"]["circuit"]["source"], circom.read_text())

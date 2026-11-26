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
            source = workspace / "inc.fth"
            source.write_text("bsv-effect: inc u32 -- u32 ;\n: inc 1 cell>u32 u32+ ;\n", encoding="utf-8")
            capabilities = json.loads(subprocess.check_output([sys.executable, "-I", str(compiler), "--capabilities"],
                                                              **options))
            self.assertEqual(capabilities["project"], "4thGraph")
            build = json.loads(subprocess.check_output(
                [sys.executable, "-I", str(compiler), str(source), "--entry", "inc", "--optimize", "safe"], **options,
            ))
            self.assertEqual(build["entry"], "inc")
            self.assertEqual(build["takes"], ["u32"])
            self.assertEqual(build["gives"], ["u32"])
            self.assertTrue(bytes.fromhex(build["script_hex"]))
            help_text = subprocess.check_output([sys.executable, "-I", str(report), "--help"], **options)
            self.assertIn(b"--output-dir", help_text)

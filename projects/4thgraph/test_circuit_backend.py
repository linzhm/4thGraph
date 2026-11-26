"""Check the bounded circuit interface and its diagnostics."""

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from circuit_backend import compile_circuit
from compiler import CompileError

SOURCE = Path(__file__).with_name("proof").joinpath("workflow.fth").read_bytes()


class CircuitBackendTests(unittest.TestCase):
    def test_declared_relation_reports_available_build_modes(self):
        protocol = Path(__file__).with_name("protocol.py")
        cli = [sys.executable, str(protocol)]
        syntax = json.loads(subprocess.check_output([*cli, "--capabilities"]))["bsv"]["source_syntax"]
        self.assertIn("relation:", syntax["parse_only_declarations"])
        self.assertEqual(syntax["legacy_aliases"]["verify:"], "relation:")
        with TemporaryDirectory() as temp:
            source = Path(temp) / "relation.fth"
            for declaration in ("relation:", "verify:"):
                with self.subTest(declaration=declaration):
                    source.write_bytes(SOURCE + b"\nREQUIRE stdlib/verify.fth\n: choose ( u32 -- route ) decide ;\n"
                                       + declaration.encode() + b" advance choose ;\n")
                    with self.assertRaisesRegex(CompileError, "parse-only"):
                        compile_circuit(source.read_bytes())
                    for options in ([], ["--keys", str(source.with_name("missing-keys.json"))]):
                        result = subprocess.run([*cli, str(source), *options], capture_output=True, text=True)
                        self.assertEqual(result.returncode, 2)
                        self.assertIn("relation: is parse-only", result.stderr)
                        self.assertIn("--entry choose", result.stderr)
                    entry = json.loads(subprocess.check_output([*cli, str(source), "--entry", "choose"]))
                    self.assertEqual(entry["entry"], "choose")
                    self.assertTrue(entry["script_hex"])

    def test_generated_circuit_is_deterministic_and_exposes_both_results(self):
        code = compile_circuit(SOURCE)
        self.assertEqual(code, compile_circuit(SOURCE))
        for declaration in (b"signal output next;", b"signal output route;", b"Bits(32)", b"Bits(33)"):
            self.assertIn(declaration, code)

    def test_standard_word_that_cannot_lower_reports_its_position(self):
        source = SOURCE.replace(b"1 cell>u32 u32+", b"u32>cell 1 + cell>u32")
        with self.assertRaisesRegex(CompileError, r"line 3, column 11: 'u32>cell' is outside"):
            compile_circuit(source)

    def test_unsupported_word_in_constant_branch_is_reported(self):
        source = SOURCE.replace(b"1 cell>u32 u32+", b"0 IF u32>cell cell>u32 THEN")
        with self.assertRaisesRegex(CompileError, r"line 3, column 16: 'u32>cell' is outside"):
            compile_circuit(source)

    def test_wire_budget_reports_the_source_operation(self):
        source = SOURCE.replace(b"1 cell>u32 u32+", b" ".join((b"1 cell>u32 u32+",) * 12))
        with self.assertRaisesRegex(CompileError, r"line 3, column \d+: generated circuit exceeds"):
            compile_circuit(source)


if __name__ == "__main__":
    unittest.main()

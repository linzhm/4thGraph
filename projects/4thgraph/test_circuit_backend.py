"""Check the bounded circuit interface and its diagnostics."""

from pathlib import Path
import unittest

from circuit_backend import compile_circuit
from compiler import CompileError

SOURCE = Path(__file__).with_name("proof").joinpath("workflow.fth").read_bytes()


class CircuitBackendTests(unittest.TestCase):
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

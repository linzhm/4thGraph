"""Check the bounded circuit interface and its diagnostics."""

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from circuit_backend import compile_circuit, parse_circuit, select_circuit
from compiler import CompileError, SourceCompiler

PROOF = Path(__file__).with_name("proof")
WORKFLOW = PROOF / "workflow.fth"
SOURCE = WORKFLOW.read_bytes()
RULES = (PROOF / "counter.fth").read_bytes()
CUSTOM = (PROOF / "step-by-three.fth").read_bytes()


class CircuitBackendTests(unittest.TestCase):
    def test_generated_circuit_is_deterministic_and_exposes_both_results(self):
        code = compile_circuit(SOURCE, source_path=WORKFLOW)
        self.assertEqual(code, compile_circuit(SOURCE, source_path=WORKFLOW))
        self.assertEqual(sha256(code).hexdigest(), "b7d12419770e4cd1cd4b8d72714be311e84cbbf224858045b7b36448d44ce679")
        for declaration in (b"signal output next;", b"signal output route;", b"Bits(32)", b"Bits(33)"):
            self.assertIn(declaration, code)

    def test_packaged_relation_can_move_with_its_shared_rules(self):
        app = PROOF.parent / "examples" / "verify-state.fth"
        source = app.read_bytes()
        reference = parse_circuit(source, source_path=app).describe()
        self.assertEqual(reference["entries"]["route"]["module"], "../proof/counter.fth")
        with TemporaryDirectory() as directory:
            copy = Path(directory) / "examples" / app.name
            copy.parent.mkdir()
            copy.write_bytes(source)
            proof = copy.parent.parent / "proof"
            proof.mkdir()
            (proof / "counter.fth").write_bytes(RULES)
            self.assertEqual(parse_circuit(copy.read_bytes(), source_path=copy).describe(), reference)
            self.assertEqual(compile_circuit(source, source_path=copy), compile_circuit(SOURCE, source_path=WORKFLOW))

    def test_standard_word_that_cannot_lower_reports_its_position(self):
        source = RULES.replace(b"1 cell>u32 u32+", b"u32>cell 1 + cell>u32")
        with self.assertRaisesRegex(CompileError, r"line 2, column 26: 'u32>cell' is outside"):
            compile_circuit(source, entries=("advance", "decide"))

    def test_unsupported_word_in_constant_branch_is_reported(self):
        source = RULES.replace(b"1 cell>u32 u32+", b"0 IF u32>cell cell>u32 THEN")
        with self.assertRaisesRegex(CompileError, r"line 2, column 31: 'u32>cell' is outside"):
            compile_circuit(source, entries=("advance", "decide"))

    def test_wire_budget_reports_the_source_operation(self):
        source = RULES.replace(b"1 cell>u32 u32+", b" ".join((b"1 cell>u32 u32+",) * 12))
        with self.assertRaisesRegex(CompileError, r"line 2, column \d+: generated circuit exceeds"):
            compile_circuit(source, entries=("advance", "decide"))

    def test_entries_follow_workflow_dependencies_and_ignore_legacy_names(self):
        source = CUSTOM + RULES
        program = select_circuit(SourceCompiler(source.decode()))
        self.assertEqual(program.describe()["entries"]["transition"]["word"], "add-three")
        self.assertEqual(program.describe()["entries"]["route"]["word"], "choose-destination")
        self.assertEqual(program.describe()["selection"], "workflow")
        self.assertEqual(compile_circuit(source), compile_circuit(CUSTOM))
        self.assertNotEqual(compile_circuit(source), compile_circuit(SOURCE, source_path=WORKFLOW))
        with self.assertRaisesRegex(CompileError, r"line \d+, column \d+: circuit entries must match"):
            compile_circuit(source, entries=("advance", "decide"))

    def test_explicit_entries_compile_a_definitions_only_source(self):
        definitions = CUSTOM.split(b"workflow-input:")[0]
        entries = ("ADD-THREE", "Choose-Destination")
        selected = select_circuit(SourceCompiler(definitions.decode()), entries)
        self.assertEqual(selected.describe()["selection"], "explicit")
        self.assertEqual(compile_circuit(definitions, entries=entries), compile_circuit(CUSTOM))
        with self.assertRaisesRegex(CompileError, r"line 4, column 3: .*requires stack effect u32 -- u32"):
            compile_circuit(definitions, entries=reversed(entries))
        with self.assertRaisesRegex(CompileError, "undefined circuit word 'missing'"):
            compile_circuit(definitions, entries=("missing", entries[1]))
        with self.assertRaisesRegex(CompileError, "a transition word and a route word"):
            compile_circuit(definitions, entries=entries[:1])

    def test_definitions_alone_require_explicit_entries(self):
        with self.assertRaisesRegex(CompileError, "--entries"):
            compile_circuit(RULES)
        self.assertEqual(compile_circuit(RULES, entries=("advance", "decide")),
                         compile_circuit(SOURCE, source_path=WORKFLOW))


if __name__ == "__main__":
    unittest.main()

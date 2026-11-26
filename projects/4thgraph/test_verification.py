"""Build declared relations through the public entry points and check their state transitions."""

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from circuit_backend import compile_circuit
from compiler import CompileError, SourceCompiler
from replay import TestKeys
from shared.benchmark_validation import chain_verdict
from shared.transaction import Input, Transaction
from verification import compile_solutions


class VerificationTests(unittest.TestCase):
    def test_cli_and_circuit_resolve_the_same_local_words(self):
        cli = [sys.executable, str(Path(__file__).with_name("protocol.py"))]
        syntax = json.loads(subprocess.check_output([*cli, "--capabilities"]))["bsv"]["source_syntax"]
        self.assertEqual(syntax["relation_backends"], ["script", "r1cs", "groth16-bls12-381"])
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "rules.fth").write_text(": plus-three ( u32 -- u32 ) 3 cell>u32 u32+ ;\n"
                                              ": choose ( u32 -- route ) 12 cell>u32 u32< "
                                              "IF route-review ELSE route-settle THEN ;\n")
            source = folder / "app.fth"
            source.write_text("REQUIRE stdlib/verify.fth\nREQUIRE rules.fth\nrelation: plus-three choose ;\n")
            keys = TestKeys().public
            key_file = folder / "keys.json"
            key_file.write_text(json.dumps({name: value.hex() for name, value in keys.items()}))
            frontend = SourceCompiler(source.read_text(), source_path=source)
            built = json.loads(subprocess.check_output([*cli, str(source), "--keys", str(key_file), "--current", "9"]))
            self.assertEqual(built["compilations"]["circuit"]["source"].encode(),
                             compile_circuit(source.read_bytes(), source_path=source))
            for current, next_state, route in ((8, 11, 0), (9, 12, 1), (0xffffffff, 2, 0)):
                with self.subTest(current=current):
                    candidate, report = compile_solutions(frontend, keys, current, temp)
                    contract = candidate.contract
                    self.assertEqual(report["selected"], "script")
                    if current == 9:
                        self.assertEqual(built["artifact_sha256"], report["artifact_sha256"])
                    parent = Transaction((Input(bytes(32), 0),), (contract.root,))
                    tx = contract.unsigned(parent, next_state)
                    self.assertEqual(tx.outputs[0], contract.terminals[route])
                    self.assertTrue(chain_verdict(candidate.seal(tx), (parent,)))
            with self.assertRaisesRegex(CompileError, "no verification path is eligible"):
                compile_solutions(frontend, keys, 19, temp, policy="require-groth16")
            with self.assertRaisesRegex(CompileError, "exceeds.*expansion budget"):
                compile_solutions(frontend, keys, 19, temp, max_expansion=1)


if __name__ == "__main__":
    unittest.main()

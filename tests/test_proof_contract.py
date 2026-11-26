"""Check verifier specialization with an independent small constraint fixture."""

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fourthgraph.verification.proof_contract import FIELD, ProofContract, VerificationKey
from fourthgraph.verification.circuit_backend import compile_circuit
from fourthgraph.verification.circuit_tools import CircuitFixture
from fourthgraph.replay.workflow import TestKeys
from fourthgraph.benchmark.validation import chain_verdict
from fourthgraph.bsv.transaction import Input, Transaction

SOURCE = b"""bsv-effect: decide u32 -- route ;
: decide 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;
"""


class ProofContractTests(unittest.TestCase):
    def test_external_r1cs_must_match_the_declared_constraints(self):
        source = SOURCE + b"REQUIRE stdlib/verify.fth\n: advance ( u32 -- u32 ) ;\nrelation: advance decide ;\n"
        generated = VerificationKey(6, (((), (), ((1, 1), (3, FIELD - 1))),), "generated", 2)
        foreign = replace(generated, constraints=(((), (), ((1, 1), (3, 1))),))

        def compile_fixture(fixture, circom, directory, *, has_route):
            self.assertTrue(has_route)
            self.assertIn(b"next <== current;", circom)
            fixture.key = generated

        with patch.object(CircuitFixture, "__init__", compile_fixture):
            with self.assertRaisesRegex(ValueError, "supplied R1CS does not match"):
                ProofContract(source, foreign, 19, TestKeys().public)
            contract = ProofContract(source, replace(generated, sha256="different-json"), 19, TestKeys().public)
            self.assertEqual(contract.key.constraints, generated.constraints)

    def test_specialization_keeps_public_binding_and_exact_equation(self):
        source = {"prime": str(FIELD), "useCustomGates": False, "nVars": 5, "nOutputs": 1,
                  "nPubInputs": 3, "nPrvInputs": 0, "nConstraints": 1,
                  "constraints": [[{}, {}, {"1": "1", "2": str(FIELD - 1), "0": str(FIELD - 1)}]]}
        key = VerificationKey.load(json.dumps(source).encode())
        declared = SOURCE + b"REQUIRE stdlib/verify.fth\n: advance ( u32 -- u32 ) ;\nrelation: advance decide ;\n"
        with self.assertRaisesRegex(ValueError, "must expose both next state and route"):
            ProofContract(declared, key, 19, TestKeys().public)
        sizes = []
        for mode in ("baseline", "stack"):
            contract = ProofContract(SOURCE, key, 19, TestKeys().public, target="both", optimization=mode)
            sizes.append(len(contract.root.script))
            parent = Transaction((Input(bytes(32), 0),), (contract.root,))
            correct = contract.unsigned(parent, 20)
            binding = contract.public_binding(correct)
            assignment = (1, 20, 19, *binding)
            self.assertTrue(chain_verdict(contract.seal(correct, assignment), (parent,)))
            self.assertFalse(chain_verdict(contract.seal(correct, (1, 21, 19, *binding)), (parent,)))
            self.assertFalse(chain_verdict(contract.seal(replace(correct, locktime=1), assignment), (parent,)))
            other = Transaction((Input(b"\x01" * 32, 0),), (contract.root,))
            self.assertFalse(chain_verdict(contract.seal(contract.unsigned(other, 20), assignment), (other,)))
        self.assertLess(sizes[-1], sizes[0])
        with self.assertRaisesRegex(ValueError, "integer field element"):
            key.assignment(b'[1, 3.1, 1, 1, 1]')

    def test_selected_route_controls_the_actual_successor(self):
        source = (Path(__file__).resolve().parents[1] / "projects/proof-counter/step-by-three.fth").read_bytes()
        definition_source = source.split(b"workflow-input:")[0]
        with TemporaryDirectory() as directory:
            fixture = CircuitFixture(compile_circuit(source), directory, has_route=True)
            keys = TestKeys().public
            workflow = ProofContract(source, fixture, 9, keys)
            explicit = ProofContract(definition_source, fixture, 9, keys, entries=("add-three", "choose-destination"))
            self.assertEqual(workflow.root, explicit.root)
            self.assertEqual(explicit.describe()["circuit"]["entries"]["route"]["word"], "choose-destination")
            parent = Transaction((Input(bytes(32), 0),), (explicit.root,))
            correct = explicit.unsigned(parent, 12)
            self.assertEqual(correct.outputs[0], explicit.terminals[1])
            assignment = fixture.prove(current=9, binding=explicit.public_binding(correct))
            self.assertTrue(chain_verdict(explicit.seal(correct, assignment), (parent,)))
            incorrect = replace(correct, outputs=(explicit.terminals[0], correct.outputs[1]))
            assignment = fixture.prove(current=9, binding=explicit.public_binding(incorrect))
            self.assertFalse(chain_verdict(explicit.seal(incorrect, assignment), (parent,)))


if __name__ == "__main__":
    unittest.main()

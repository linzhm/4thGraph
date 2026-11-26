"""Check verifier specialization with an independent small constraint fixture."""

import json
import unittest

from proof_contract import FIELD, ProofContract, VerificationKey
from replay import TestKeys
from shared.benchmark_validation import chain_verdict
from shared.transaction import Input, Transaction

SOURCE = b"""bsv-effect: decide u32 -- route ;
: decide 20 cell>u32 u32< IF route-review ELSE route-settle THEN ;
"""


class ProofContractTests(unittest.TestCase):
    def test_specialization_keeps_public_binding_and_exact_equation(self):
        source = {"prime": str(FIELD), "useCustomGates": False, "nVars": 5, "nOutputs": 1,
                  "nPubInputs": 3, "nPrvInputs": 0, "nConstraints": 1,
                  "constraints": [[{}, {}, {"1": "1", "2": str(FIELD - 1), "0": str(FIELD - 1)}]]}
        key = VerificationKey.load(json.dumps(source).encode())
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
            other = Transaction((Input(b"\x01" * 32, 0),), (contract.root,))
            self.assertFalse(chain_verdict(contract.seal(contract.unsigned(other, 20), assignment), (other,)))
        self.assertLess(sizes[-1], sizes[0])
        with self.assertRaisesRegex(ValueError, "integer field element"):
            key.assignment(b'[1, 3.1, 1, 1, 1]')


if __name__ == "__main__":
    unittest.main()

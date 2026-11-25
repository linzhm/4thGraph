import json
from pathlib import Path
import unittest

from committed_verifier import load_artifact, verifier_fields
from continuity_chain_proof import _recover
from verifier import unlocking_script


class ChainProofRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / "continuity/testdata/recursive-two.json"
        cls.proof_file = json.loads(path.read_text())
        proof_keys = {"proof_a", "proof_b", "proof_c", "commitment", "commitment_knowledge_proof",
                      "public_signals", "continuity"}
        cls.key_file = {k: v for k, v in cls.proof_file.items() if k not in proof_keys}
        key, relation, cls.signals, proof = load_artifact(cls.proof_file)
        cls.fields = verifier_fields(key, relation, cls.signals, proof)
        cls.script = unlocking_script(cls.fields)

    def test_extracts_native_proof_with_only_key_and_chain_fields(self):
        recovered = _recover(self.key_file, self.signals, self.script + b"suffix")
        self.assertEqual(recovered, {k: v for k, v in self.proof_file.items() if k != "continuity"})

    def test_rejects_different_statement_noncanonical_push_and_changed_hint(self):
        with self.assertRaises(ValueError):
            _recover(self.key_file, (self.signals[0] ^ 1, self.signals[1]), self.script)
        for witness in (self.script[:-1], b"\x4c" + self.script,
                        unlocking_script((self.fields[0] ^ 1, *self.fields[1:]))):
            with self.subTest(size=len(witness)), self.assertRaises(ValueError):
                _recover(self.key_file, self.signals, witness)

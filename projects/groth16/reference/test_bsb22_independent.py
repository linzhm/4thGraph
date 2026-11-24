"""Use the BSB22 verifier with an independently generated arithmetic proof."""

import json
from pathlib import Path
import unittest
from dataclasses import replace

from bsb22 import CommittedProof, CommitmentRelation, standalone_witness, verifier_fields, verifier_lock
from shared.evaluate import ScriptError, evaluate
from shared.script import number
from snarkjs_adapter import point
from verifier import Proof, VerificationKey, unlocking_script


def arithmetic_fixture():
    data = json.loads((Path(__file__).parent / "testdata" / "bsb22-arithmetic.json").read_text())
    key = VerificationKey(
        point(data["alpha"]), point(data["beta"], twist=True), point(data["gamma"], twist=True),
        point(data["delta"], twist=True), tuple(point(item, allow_infinity=True) for item in data["ic"]),
    )
    relation = CommitmentRelation(
        point(data["commitment_g2"], twist=True), point(data["commitment_g2_sigma_neg"], twist=True),
    )
    proof = CommittedProof(
        Proof(point(data["a"]), point(data["b"], twist=True), point(data["c"])),
        point(data["commitment"]), point(data["pok"]),
    )
    return key, relation, tuple(map(int, data["public_inputs"])), proof


class IndependentBSB22Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.relation, cls.signals, cls.proof = arithmetic_fixture()
        cls.lock = verifier_lock(cls.key, cls.relation)
        cls.witness = standalone_witness(cls.key, cls.relation, cls.signals, cls.proof)

    def test_verifies_independent_arithmetic_circuit(self):
        self.assertEqual(self.signals, (16, 55))
        self.assertEqual(evaluate(self.witness + self.lock), ([b"\x01"], []))

    def test_rejects_changed_input_and_incompatible_verifier_key(self):
        high, low = self.signals
        fields = verifier_fields(self.key, self.relation, self.signals, self.proof)
        changed = unlocking_script(fields) + number(high) + number(low + 1)
        incompatible = replace(self.key, gamma=self.key.delta)
        for unlocking, locking in (
            (changed, self.lock),
            (self.witness, verifier_lock(incompatible, self.relation)),
        ):
            with self.assertRaises(ScriptError):
                evaluate(unlocking + locking)

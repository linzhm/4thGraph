"""The PoK must open the exact commitment under the configured G2 points."""
from importlib.util import find_spec
import unittest

from fixtures import G1, G2
from shared.evaluate import evaluate, ScriptError
from shared.transaction import Input, Output, Transaction, hash256
from verifier import Curve, Host

from pedersen import knowledge_lock, knowledge_witness


class KnowledgeTests(unittest.TestCase):
    def test_accepts_pok_and_rejects_crossed_commitments_with_recomputed_residues(self):
        g1 = Curve(Host())
        g2 = Curve(Host(), twist=True)
        sigma_neg = g2.negate(g2.mul_host(G2, 17))
        commit = g1.mul_host(G1, 27)
        opening = g1.mul_host(commit, 17)
        other = g1.mul_host(G1, 29)
        lock = knowledge_lock(G2, sigma_neg)
        valid = knowledge_witness(commit, opening, G2, sigma_neg)
        self.assertEqual(evaluate(valid + lock), ([b'\x01'], []))
        crossed = knowledge_witness(other, opening, G2, sigma_neg)
        with self.assertRaises(ScriptError):
            evaluate(crossed + lock)
        if find_spec("tx_engine") is not None:
            from shared.chain_gang import validate_at_heights

            parent = Transaction((Input(hash256(b"BSB22 test parent"), 0),), (Output(2, lock),))
            spend = Transaction((Input(parent.txid_wire(), 0, valid),), (Output(1, b'\x51'),))
            validate_at_heights(spend, (parent,), spend_height=100, activation_height=2, utxo_heights=(3,))

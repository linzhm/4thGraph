from importlib.util import find_spec
import unittest

from compiler import Program
from shared.evaluate import evaluate, ScriptError
from shared.transaction import Input, Output, Transaction, hash256
from verifier import unlocking_script

from short_mimc import ROUNDS, VECTOR, commitment_challenge


class ShortMiMCTests(unittest.TestCase):
    def test_script_matches_gnark_commitment_challenge(self):
        self.assertEqual(ROUNDS, tuple(int(value, 16) for value in VECTOR["round_constants"]))
        program = Program()
        commitment = tuple(program.wire_field() for _ in range(2))
        claimed = program.wire_field()
        challenge = commitment_challenge(program, commitment)
        program.zero(program.sub(challenge, claimed))
        lock, _, _ = program.compile(reuse_constants=True)
        point = tuple(map(int, VECTOR["point"]))
        valid = unlocking_script((*point, int(VECTOR["challenge"])))
        self.assertEqual(evaluate(valid + lock), ([b'\x01'], []))
        wrong = unlocking_script((*point, int(VECTOR["challenge"]) + 1))
        with self.assertRaises(ScriptError):
            evaluate(wrong + lock)
        if find_spec("tx_engine") is not None:
            from shared.chain_gang import validate_at_heights

            parent = Transaction((Input(hash256(b"short MiMC test parent"), 0),), (Output(2, lock),))
            spend = Transaction((Input(parent.txid_wire(), 0, valid),), (Output(1, b'\x51'),))
            validate_at_heights(spend, (parent,), spend_height=100, activation_height=2, utxo_heights=(3,))

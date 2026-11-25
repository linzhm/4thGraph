"""Dynamic Groth16 input combination checks in the interpreter and chain-gang."""

from dataclasses import replace
from functools import cache
import unittest

from shared.evaluate import ScriptError, evaluate
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, preimage_forkid

from fixtures import G1, fixture
from public_inputs import public_input_check, verification_key_point
from transfer import TransferStatement, statement_script
from verifier import Curve, Host


@cache
def sample():
    key, _, _ = fixture()
    return key.ic, public_input_check(key.ic)


def witness(point):
    x, y = point if point is not None else (0, 0)
    return number(y) + number(x)


class PublicInputTests(unittest.TestCase):
    def test_exact_msm_and_large_limbs(self):
        ic, lock = sample()
        for limbs in ((0, 0), (2**128 - 1, 2**127 + 1)):
            with self.subTest(limbs=limbs):
                point = verification_key_point(ic, limbs)
                scalars = b"".join(map(number, limbs))
                self.assertEqual(evaluate(witness(point) + scalars + lock), ([b"\x01"], []))
                with self.assertRaises(ScriptError):
                    evaluate(witness((0, 0)) + scalars + lock)
        with self.assertRaises(ScriptError):
            evaluate(witness((0, 0)) + number(2**128) + number(0) + lock)

    def test_complete_addition_edges(self):
        opposite = Curve(Host()).negate(G1)
        ic = G1, opposite, G1
        lock = public_input_check(ic)
        for limbs, expected in (((1, 0), None), ((1, 1), G1), ((0, 1), Curve(Host()).add_host(G1, G1))):
            self.assertEqual(verification_key_point(ic, limbs), expected)
            self.assertEqual(evaluate(witness(expected) + b"".join(map(number, limbs)) + lock), ([b"\x01"], []))

    def test_actual_transaction_drives_msm(self):
        from shared.chain_gang import validate_at_heights

        ic, msm_lock = sample()
        issuance = b"\x43" * 36
        lock = statement_script(issuance) + msm_lock
        funding = Transaction((Input(bytes.fromhex("01" * 32), 0),), (Output(1_000, lock),))
        payment = Transaction((Input(funding.txid_wire(), 0),), (Output(900, asm("OP_1")),))

        def with_point(tx, point):
            preimage = preimage_forkid(tx, 0, 1_000, lock, 0x41)
            return tx.with_script(0, witness(point) + push(preimage))

        def expected(tx):
            return verification_key_point(ic, TransferStatement(issuance, lock).public_inputs(tx, 0, funding))

        point = expected(payment)
        changed = replace(payment, outputs=(Output(899, asm("OP_1")),))
        for spend_height, creation_height in ((2, 1), (4, 1), (4, 3)):
            context = dict(spend_height=spend_height, activation_height=3, utxo_heights=[creation_height])
            validate_at_heights(with_point(payment, point), [funding], **context)
            validate_at_heights(with_point(changed, expected(changed)), [funding], **context)
            with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                validate_at_heights(with_point(changed, point), [funding], **context)

    def test_one_real_groth16_proof_for_two_guarded_inputs(self):
        from shared.chain_gang import validate_at_heights
        from public_inputs import transaction_verifier_lock, transaction_verifier_unlock
        from transfer import verifier_input_guard

        key, _, _ = fixture()
        issuance = b"\x57" * 36
        lock = transaction_verifier_lock(issuance, key)
        guarded_lock = verifier_input_guard(lock) + asm("OP_1")
        funding = [
            Transaction((Input(bytes([i]) * 32, 0),), (Output(1_000, script),))
            for i, script in enumerate((lock, guarded_lock, guarded_lock), 1)
        ]
        payment = Transaction(
            tuple(Input(parent.txid_wire(), 0) for parent in funding),
            (Output(2_000, asm("OP_1")), Output(900, asm("OP_2"))),
        )
        statement = TransferStatement(issuance, lock)
        high, low = statement.public_inputs(payment, 0, funding[0])
        # The fixture circuit checks public output = private product + public offset.
        from field import R

        _, generated, proof = fixture(1, (high - low) % R, low)
        self.assertEqual(generated, (high, low))

        def build(tx):
            prevouts = b"".join(txin.outpoint() for txin in tx.inputs)
            tx = tx.with_script(0, transaction_verifier_unlock(statement, tx, 0, funding[0], key, proof))
            for index in (1, 2):
                preimage = preimage_forkid(tx, index, 1_000, guarded_lock, 0x41)
                tx = tx.with_script(index, push(funding[0].serialize()) + push(prevouts) + push(preimage))
            return tx

        context = dict(spend_height=4, activation_height=3, utxo_heights=[3, 3, 3])
        validate_at_heights(build(payment), funding, **context)
        changed = replace(payment, outputs=(payment.outputs[0], Output(899, asm("OP_2"))))
        with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
            validate_at_heights(build(changed), funding, **context)

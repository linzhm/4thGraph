"""Reference checks for the public statement before compiling the covenant."""

from dataclasses import replace
import unittest

from shared.transaction import Input, Output, Transaction
from transfer import TransferStatement


def example(nonce):
    funding = Transaction((Input(bytes([nonce]) * 32, 0),), (Output(1_000, b"verifier"),))
    payment = Transaction(
        (Input(bytes([nonce + 1]) * 32, 0), Input(funding.txid_wire(), 0)),
        (Output(900, b"recipient"), Output(100, b"change")),
    )
    return funding, payment


class TransferStatementTests(unittest.TestCase):
    def setUp(self):
        self.statement = TransferStatement(b"\x42" * 36, b"verifier")
        self.funding, self.payment = example(1)

    def test_actual_payment_and_change_are_bound(self):
        tx = self.payment
        expected = self.statement.public_inputs(tx, 1, self.funding)
        changes = (
            replace(tx, inputs=(replace(tx.inputs[0], vout=1), tx.inputs[1])),
            replace(tx, outputs=(replace(tx.outputs[0], script=b"other"), tx.outputs[1])),
            replace(tx, outputs=(tx.outputs[0], replace(tx.outputs[1], value=99))),
            replace(tx, outputs=tuple(reversed(tx.outputs))),
            replace(tx, locktime=11),
        )
        for candidate in changes:
            self.assertNotEqual(self.statement.public_inputs(candidate, 1, self.funding), expected)
        self.assertEqual(
            self.statement.public_inputs(tx.with_script(1, b"proof"), 1, self.funding), expected,
        )
        self.assertTrue(all(0 <= value < 2**128 for value in expected))
        self.assertNotEqual(replace(self.statement, issuance_outpoint=b"\x43" * 36)
                            .public_inputs(tx, 1, self.funding), expected)

    def test_verifier_must_be_the_referenced_output(self):
        with self.assertRaisesRegex(ValueError, "outpoint"):
            self.statement.public_inputs(self.payment, 0, self.funding)
        with self.assertRaisesRegex(ValueError, "unexpected verifier lock"):
            replace(self.statement, authorized_lock=b"other").public_inputs(self.payment, 1, self.funding)
        with self.assertRaisesRegex(ValueError, "duplicate input"):
            duplicate = replace(self.payment, inputs=self.payment.inputs + self.payment.inputs[:1])
            self.statement.public_inputs(duplicate, 1, self.funding)

    def test_disjoint_payments_use_distinct_verifier_instances(self):
        other_funding, other_payment = example(3)
        self.assertTrue({i.outpoint() for i in self.payment.inputs}.isdisjoint(
            i.outpoint() for i in other_payment.inputs
        ))
        self.assertNotEqual(self.statement.public_inputs(self.payment, 1, self.funding),
                            self.statement.public_inputs(other_payment, 1, other_funding))


class ScriptStatementTests(unittest.TestCase):
    def test_funded_verifier_outpoint_at_the_designated_input(self):
        from shared.chain_gang import validate_at_heights
        from shared.script import asm, push
        from shared.transaction import preimage_all
        from transfer import verifier_input_outpoint_guard

        first, second, other = (
            replace(example(nonce)[0], outputs=(Output(1_000, asm("OP_1")),) * 2)
            for nonce in (1, 3, 5)
        )
        first_outpoint = Input(first.txid_wire(), 1)
        second_outpoint = Input(second.txid_wire(), 0)
        other_outpoint = Input(other.txid_wire(), 0)
        approved = (first_outpoint.outpoint(), second_outpoint.outpoint())
        for allowlist in ((approved[0],), approved):
            guard = verifier_input_outpoint_guard(allowlist, input_count=3, input_index=1)
            self.assertEqual(guard, verifier_input_outpoint_guard(
                reversed(allowlist), input_count=3, input_index=1,
            ))
            lock = asm("OP_7 OP_TOALTSTACK") + guard + asm(
                "OP_8 OP_NUMEQUALVERIFY OP_FROMALTSTACK OP_7 OP_NUMEQUAL",
            )
            token = replace(example(7)[0], outputs=(Output(1_000, lock),))
            token_outpoint = Input(token.txid_wire(), 0)

            def validate(inputs, parents, *, disclosed=None, preimage=None):
                tx = Transaction((token_outpoint, *inputs), (Output(1_000, asm("OP_1")),))
                if disclosed is None:
                    disclosed = b"".join(txin.outpoint() for txin in tx.inputs)
                if preimage is None:
                    preimage = preimage_all(tx, 0, 1_000, lock)
                tx = tx.with_script(0, asm("OP_8") + push(disclosed) + push(preimage))
                validate_at_heights(tx, [token, *parents], spend_height=4, activation_height=3,
                                    utxo_heights=[3] * len(tx.inputs))

            validate((first_outpoint, other_outpoint), (first, other))
            if len(allowlist) == 2:
                validate((second_outpoint, other_outpoint), (second, other))
            original_inputs = (token_outpoint, first_outpoint, other_outpoint)
            original_prevouts = b"".join(txin.outpoint() for txin in original_inputs)
            original = Transaction(original_inputs, (Output(1_000, asm("OP_1")),))
            original_preimage = preimage_all(original, 0, 1_000, lock)
            for inputs, parents, kwargs in (
                ((other_outpoint, first_outpoint), (other, first), {}),
                ((other_outpoint, first_outpoint), (other, first), {"disclosed": original_prevouts}),
                ((other_outpoint, first_outpoint), (other, first),
                 {"disclosed": original_prevouts, "preimage": original_preimage}),
                ((replace(first_outpoint, vout=0), other_outpoint), (first, other), {}),
                ((first_outpoint,), (first,), {}),
            ):
                with self.subTest(allowlist=len(allowlist), inputs=inputs, kwargs=kwargs):
                    with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                        validate(inputs, parents, **kwargs)

    def test_outpoint_allowlist_rejects_invalid_configuration(self):
        from transfer import verifier_input_outpoint_guard

        outpoint = bytes(36)
        for approved, count, index in (((), 2, 1), ((bytes(35),), 2, 1),
                                       ((outpoint, outpoint), 2, 1), ((outpoint,), 0, 0),
                                       ((outpoint,), 2, 2), ((outpoint,), 2, -1)):
            with self.subTest(approved=approved, count=count, index=index):
                with self.assertRaises(ValueError):
                    verifier_input_outpoint_guard(approved, input_count=count, input_index=index)

    def test_authenticated_current_input(self):
        from shared.chain_gang import validate_at_heights
        from shared.script import asm, number, push
        from shared.transaction import preimage_forkid
        from transfer import statement_script

        issuance = b"\x42" * 36
        # The harness compares both stack results against supplied expectations.
        lock = statement_script(issuance) + asm("OP_ROT OP_NUMEQUALVERIFY OP_NUMEQUAL")
        fee_parent, _ = example(1)
        funding = replace(fee_parent, outputs=(Output(1_000, lock),))
        payment = Transaction(
            (Input(funding.txid_wire(), 0),),
            (Output(800, asm("OP_1")), Output(100, asm("OP_2"))),
        )
        high, low = TransferStatement(issuance, lock).public_inputs(payment, 0, funding)
        preimage = preimage_forkid(payment, 0, 1_000, lock, 0x41)

        def unlock(data, expected=high):
            return number(expected) + number(low) + push(data)

        context = dict(spend_height=4, activation_height=3, utxo_heights=[3])
        validate_at_heights(payment.with_script(0, unlock(preimage)), [funding], **context)
        changed_change = replace(payment, outputs=(payment.outputs[0], Output(99, asm("OP_2"))))
        for tx, witness in (
            (payment, unlock(preimage, high ^ 1)),
            (payment, unlock(preimage[:-4] + b"\xc1\x00\x00\x00")),
            (changed_change, unlock(preimage)),
        ):
            with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                validate_at_heights(tx.with_script(0, witness), [funding], **context)

    def test_two_token_inputs_authenticate_the_same_verifier(self):
        from shared.chain_gang import validate_at_heights
        from shared.script import asm, number, push
        from shared.transaction import preimage_forkid
        from transfer import statement_script, verifier_input_guard

        issuance = b"\x42" * 36
        verifier_lock = statement_script(issuance) + asm("OP_ROT OP_NUMEQUALVERIFY OP_NUMEQUAL")
        token_lock = verifier_input_guard(verifier_lock) + asm("OP_1")
        parents = [
            replace(example(nonce)[0], outputs=(Output(1_000, lock),))
            for nonce, lock in ((1, verifier_lock), (3, token_lock), (5, token_lock))
        ]
        payment = Transaction(
            tuple(Input(parent.txid_wire(), 0) for parent in parents),
            (Output(2_500, asm("OP_1")),),
        )

        def sign(tx, funding):
            prevouts = b"".join(txin.outpoint() for txin in tx.inputs)
            for index, parent in enumerate(funding):
                lock = parent.outputs[0].script
                preimage = preimage_forkid(tx, index, 1_000, lock, 0x41)
                if index == 0 and lock == verifier_lock:
                    high, low = TransferStatement(issuance, lock).public_inputs(tx, index, parent)
                    witness = number(high) + number(low) + push(preimage)
                elif index > 0:
                    witness = push(funding[0].serialize()) + push(prevouts) + push(preimage)
                else:
                    witness = b""
                tx = tx.with_script(index, witness)
            return tx

        context = dict(spend_height=4, activation_height=3, utxo_heights=[3, 3, 3])
        validate_at_heights(sign(payment, parents), parents, **context)
        substitute = replace(parents[0], outputs=(Output(1_000, asm("OP_1")),))
        fake = replace(payment, inputs=(Input(substitute.txid_wire(), 0), *payment.inputs[1:]))
        with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
            validate_at_heights(sign(fake, [substitute, *parents[1:]]), [substitute, *parents[1:]], **context)

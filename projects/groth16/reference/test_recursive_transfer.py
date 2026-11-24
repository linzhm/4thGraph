"""Transaction-graph checks with a test-only parent proof oracle."""

from dataclasses import replace
import unittest

from shared.transaction import Input, Output, Transaction
from recursive_transfer import PriorProof, RecursiveTransfer
from token_transfer import TokenState, owned_token_lock
from transfer import TransferStatement, shared_guard_lock

ISSUANCE = Input(b"\x42" * 32, 0)
LOCK = b"verifier"
OWNER = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")


def funding(nonce):
    return Transaction((Input(bytes([nonce]) * 32, 0),), (Output(1000, LOCK),))


def output(quantity, *, shared_guard=False):
    return Output(100, owned_token_lock(TokenState(ISSUANCE.outpoint(), quantity, OWNER), LOCK, shared_guard=shared_guard))


def transfer(verifier, spent, amounts):
    inputs = (Input(verifier.txid_wire(), 0), *(Input(parent.txid_wire(), i) for parent, i in spent))
    return Transaction(inputs, tuple(map(output, amounts)))


class RecursiveTransferTests(unittest.TestCase):
    def test_split_merge_and_predecessor_reuse(self):
        genesis = Transaction((ISSUANCE,), (output(9), output(3)))
        statement = TransferStatement(ISSUANCE.outpoint(), LOCK)
        relation = RecursiveTransfer(statement, 12)
        split_verifier, final_verifier = funding(1), funding(2)
        split = transfer(split_verifier, ((genesis, 0), (genesis, 1)), (4, 8))

        def unexpected(*_):
            self.fail("issuance should use the base case")

        split_inputs = relation.check(split, (split_verifier, genesis, genesis), {}, unexpected)
        calls = []

        def verify(public, proof):
            calls.append(public)
            return public == split_inputs and proof == b"test-oracle-proof"

        prior = {split.txid_wire(): PriorProof(split_verifier, b"test-oracle-proof")}
        final = transfer(final_verifier, ((split, 0), (split, 1)), (12,))
        parents = (final_verifier, split, split)
        self.assertEqual(relation.check(final, parents, prior, verify),
                         statement.public_inputs(final, 0, final_verifier))
        self.assertEqual(calls, [split_inputs])
        with self.assertRaisesRegex(ValueError, "missing parent transfer proof"):
            relation.check(final, parents, {}, verify)
        with self.assertRaisesRegex(ValueError, "quantities do not conserve"):
            relation.check(replace(final, outputs=(output(13),)), parents, prior, verify)
        with self.assertRaisesRegex(ValueError, "duplicate input"):
            relation.check(replace(final, inputs=(*final.inputs[:2], final.inputs[1])), parents, prior, verify)

        modified = replace(split, outputs=(output(5), output(7)))
        another = transfer(final_verifier, ((modified, 0), (modified, 1)), (12,))
        with self.assertRaisesRegex(ValueError, "invalid parent transfer proof"):
            relation.check(another, (final_verifier, modified, modified),
                           {modified.txid_wire(): prior[split.txid_wire()]}, verify)

    def test_32_outputs_from_distinct_and_shared_predecessors(self):
        genesis = Transaction((ISSUANCE,), (output(16), output(16)))
        statement = TransferStatement(ISSUANCE.outpoint(), LOCK)
        relation = RecursiveTransfer(statement, 32)
        verifiers = (funding(10), funding(11))
        predecessors = tuple(transfer(verifier, ((genesis, index),), (2,) * 8)
                             for index, verifier in enumerate(verifiers))
        expected = {
            relation.check(parent, (verifier, genesis), {}, lambda *_: False)
            for parent, verifier in zip(predecessors, verifiers, strict=True)
        }
        proofs = {
            parent.txid_wire(): PriorProof(verifier, b"test-oracle-proof")
            for parent, verifier in zip(predecessors, verifiers, strict=True)
        }
        calls = []

        def verify(public, proof):
            calls.append(public)
            return public in expected and proof == b"test-oracle-proof"

        verifier = funding(12)
        consumed = tuple((parent, index) for parent in predecessors for index in range(8))
        payment = transfer(verifier, consumed, (1,) * 32)
        parents = (verifier, *(parent for parent, _ in consumed))
        self.assertEqual(relation.check(payment, parents, proofs, verify),
                         statement.public_inputs(payment, 0, verifier))
        self.assertEqual(len(calls), 2)
        self.assertEqual(set(calls), expected)

    def test_shared_guard_is_required_in_the_recursive_relation(self):
        genesis = Transaction((ISSUANCE,), (output(8, shared_guard=True),))
        verifier = funding(1)
        guard = replace(funding(2), outputs=(Output(1_000, shared_guard_lock(LOCK)),))
        statement = TransferStatement(ISSUANCE.outpoint(), LOCK)
        relation = RecursiveTransfer(statement, 8, shared_guard=True)
        spend = Transaction(
            (Input(verifier.txid_wire(), 0), Input(guard.txid_wire(), 0), Input(genesis.txid_wire(), 0)),
            (output(3, shared_guard=True), output(5, shared_guard=True)),
        )
        self.assertEqual(relation.check(spend, (verifier, guard, genesis), {}, lambda *_: False),
                         statement.public_inputs(spend, 0, verifier))
        substitute = replace(guard, outputs=(Output(1_000, LOCK),))
        changed = replace(spend, inputs=(spend.inputs[0], Input(substitute.txid_wire(), 0), spend.inputs[2]))
        with self.assertRaisesRegex(ValueError, "expected shared guard at input one"):
            relation.check(changed, (verifier, substitute, genesis), {}, lambda *_: False)

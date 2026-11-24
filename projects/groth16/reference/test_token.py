"""Owner authorization and reference token transfer checks."""

from dataclasses import replace
from functools import cache
import unittest

from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_forkid

from field import R
from fixtures import fixture
from public_inputs import transaction_verifier_lock, transaction_verifier_unlock
from token_transfer import TokenState, check_transfer_relation, owned_token_lock
from transfer import TransferStatement, shared_guard_lock

ISSUANCE = b"\x23" * 36


@cache
def setup(quantities_in=(7, 5), quantities_out=(10, 2), *, shared_guard=False, compact_preimage=False):
    from ecdsa import SECP256k1, SigningKey

    # Test-only private scalars.
    owners = [SigningKey.from_secret_exponent(i, curve=SECP256k1) for i in range(17, 17 + len(quantities_in))]
    public = [owner.verifying_key.to_string("compressed") for owner in owners]
    key, _, _ = fixture()
    verifier = transaction_verifier_lock(ISSUANCE, key, compact_preimage=compact_preimage)
    scripts = [verifier]
    if shared_guard:
        scripts.append(shared_guard_lock(verifier))
    scripts.extend(owned_token_lock(TokenState(ISSUANCE, q, pk), verifier, shared_guard=shared_guard)
                   for q, pk in zip(quantities_in, public, strict=True))
    parents = tuple(Transaction((Input(i.to_bytes(32, "little"), 0),), (Output(1_000, lock),))
                    for i, lock in enumerate(scripts, 1))
    outputs = tuple(
        Output(500, owned_token_lock(
            TokenState(ISSUANCE, value, public[-1 - index % len(public)]),
            verifier, shared_guard=shared_guard,
        ))
        for index, value in enumerate(quantities_out)
    )
    tx = Transaction(tuple(Input(parent.txid_wire(), 0) for parent in parents), outputs)
    return owners, key, verifier, parents, tx


class OwnedTokenTests(unittest.TestCase):
    def test_quantity_and_provenance_reference(self):
        _, _, verifier, parents, tx = setup()
        authentic = {item.outpoint() for item in tx.inputs[1:]}
        check_transfer_relation(tx, parents, ISSUANCE, verifier, authentic)
        with self.assertRaisesRegex(ValueError, "unauthenticated token input"):
            check_transfer_relation(tx, parents, ISSUANCE, verifier, set())
        with self.assertRaisesRegex(ValueError, "quantities do not conserve"):
            check_transfer_relation(replace(tx, outputs=tx.outputs[:1]), parents,
                                    ISSUANCE, verifier, authentic)
        counterfeit_parent = replace(parents[1], locktime=1)
        counterfeit = replace(tx, inputs=(tx.inputs[0], Input(counterfeit_parent.txid_wire(), 0), tx.inputs[2]))
        with self.assertRaisesRegex(ValueError, "unauthenticated token input"):
            check_transfer_relation(counterfeit, (parents[0], counterfeit_parent, parents[2]),
                                    ISSUANCE, verifier, authentic)
        substitute = replace(tx.outputs[0], script=tx.outputs[0].script[:-1] + asm("OP_1"))
        with self.assertRaisesRegex(ValueError, "unexpected token covenant"):
            check_transfer_relation(replace(tx, outputs=(substitute, tx.outputs[1])), parents,
                                    ISSUANCE, verifier, authentic)

    def test_shared_verifier_across_transfer_shapes(self):
        for quantities_in, quantities_out in (
            ((7, 5), (12,)),
            ((12,), (10, 2)),
            ((7, 5), (10, 2)),
            ((1, 3, 5, 7), (2, 2, 4, 8)),
        ):
            with self.subTest(shape=(len(quantities_in), len(quantities_out))):
                self.check_complete_transfer(quantities_in, quantities_out)

    def test_larger_shared_verifier_transfers(self):
        for n_in, n_out in ((16, 32), (32, 32), (32, 1)):
            with self.subTest(shape=(n_in, n_out)):
                quantities_in = (32 - n_in + 1,) + (1,) * (n_in - 1)
                quantities_out = (32 - n_out + 1,) + (1,) * (n_out - 1)
                self.check_complete_transfer(quantities_in, quantities_out, rejection_cases=False)

    def check_complete_transfer(self, quantities_in, quantities_out, *, rejection_cases=True):
        from ecdsa.util import sigencode_der_canonize
        from shared.chain_gang import validate_at_heights

        owners, key, verifier, parents, payment = setup(quantities_in, quantities_out)
        authentic = {txin.outpoint() for txin in payment.inputs[1:]}
        check_transfer_relation(payment, parents, ISSUANCE, verifier, authentic)
        statement = TransferStatement(ISSUANCE, verifier)
        high, low = statement.public_inputs(payment, 0, parents[0])
        _, _, proof = fixture(1, (high - low) % R, low)

        verifier_parent = push(parents[0].serialize())

        def build(tx, signers, selected_proof):
            prevouts = b"".join(txin.outpoint() for txin in tx.inputs)
            tx = tx.with_script(0, transaction_verifier_unlock(statement, tx, 0, parents[0], key, selected_proof))
            for index, signer in enumerate(signers, 1):
                previous = parents[index].outputs[0]
                preimage = preimage_forkid(tx, index, previous.value, previous.script, 0x41)
                signature = signer.sign_digest_deterministic(hash256(preimage), sigencode=sigencode_der_canonize)
                witness = push(signature + b"\x41") + verifier_parent + push(prevouts) + push(preimage)
                tx = tx.with_script(index, witness)
            return tx

        context = dict(spend_height=4, activation_height=3, utxo_heights=[3] * len(parents))
        validate_at_heights(build(payment, owners, proof), parents, **context)
        if not rejection_cases:
            return
        first, *other_outputs = payment.outputs
        changed = replace(payment, outputs=(replace(first, value=first.value - 1), *other_outputs))
        incorrect_owners = (*owners[1:], owners[0]) if len(owners) > 1 else setup()[0][1:]
        for tx in (build(payment, incorrect_owners, proof), build(changed, owners, proof)):
            with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                validate_at_heights(tx, parents, **context)

    def test_compact_shared_guard(self):
        self.check_shared_guard(False)

    def test_shared_guard_and_short_scriptcode(self):
        self.check_shared_guard(True)

    def check_shared_guard(self, compact_preimage):
        from ecdsa.util import sigencode_der_canonize
        from shared.chain_gang import validate_at_heights

        for n_in, n_out in ((1, 2), (4, 4), (16, 32), (32, 32), (64, 64), (256, 256)):
            with self.subTest(shape=(n_in, n_out)):
                total = max(32, n_in, n_out)
                owners, key, verifier, parents, payment = setup(
                    (total - n_in + 1,) + (1,) * (n_in - 1),
                    (total - n_out + 1,) + (1,) * (n_out - 1),
                    shared_guard=True, compact_preimage=compact_preimage,
                )
                authentic = {txin.outpoint() for txin in payment.inputs[2:]}
                check_transfer_relation(payment, parents, ISSUANCE, verifier, authentic, shared_guard=True)
                statement = TransferStatement(ISSUANCE, verifier, compact_preimage=compact_preimage)

                def verifier_witness(tx, parent, checked_statement):
                    high, low = checked_statement.public_inputs(tx, 0, parent)
                    _, _, proof = fixture(1, (high - low) % R, low)
                    return transaction_verifier_unlock(checked_statement, tx, 0, parent, key, proof)

                def build(tx, funding, checked_statement=statement):
                    prevouts = push(b"".join(txin.outpoint() for txin in tx.inputs))
                    if funding[0].outputs[0].script == checked_statement.authorized_lock:
                        tx = tx.with_script(0, verifier_witness(tx, funding[0], checked_statement))
                    if funding[1].outputs[0].script == shared_guard_lock(verifier):
                        prev = funding[1].outputs[0]
                        preimage = preimage_forkid(tx, 1, prev.value, prev.script, 0x41)
                        tx = tx.with_script(1, push(funding[0].serialize()) + prevouts + push(preimage))
                    guard_parent = push(funding[1].serialize())
                    for index, signer in enumerate(owners, 2):
                        prev = funding[index].outputs[0]
                        preimage = preimage_forkid(tx, index, prev.value, prev.script, 0x41)
                        signature = signer.sign_digest_deterministic(
                            hash256(preimage), sigencode=sigencode_der_canonize,
                        )
                        tx = tx.with_script(index, push(signature + b"\x41") + guard_parent + prevouts + push(preimage))
                    return tx

                context = dict(spend_height=4, activation_height=3, utxo_heights=[3] * len(parents))
                signed = build(payment, parents)
                validate_at_heights(signed, parents, **context)
                self.assertTrue(all(len(txin.script) < len(verifier) for txin in signed.inputs[2:]))
                if compact_preimage:
                    self.assertLess(len(signed.inputs[0].script), 1500)
                if n_in != 4:
                    continue
                if compact_preimage:
                    # Re-sign all other inputs for a changed payment. At vin[0] keep
                    # the old proof and its matching old short preimage together.
                    first, *rest = payment.outputs
                    changed = replace(payment, outputs=(replace(first, value=first.value - 1), *rest))
                    stale = build(changed, parents).with_script(0, signed.inputs[0].script)
                    with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                        validate_at_heights(stale, parents, **context)

                    # Same post-separator scriptCode, different prevout and verifier commitment.
                    alternate_lock = asm("OP_NOP") + verifier
                    alternate_parent = replace(parents[0], outputs=(Output(1000, alternate_lock),))
                    alternate_statement = replace(statement, authorized_lock=alternate_lock)
                    standalone = Transaction((Input(alternate_parent.txid_wire(), 0),), (Output(900, asm("OP_1")),))
                    standalone = standalone.with_script(
                        0, verifier_witness(standalone, alternate_parent, alternate_statement),
                    )
                    validate_at_heights(standalone, [alternate_parent], **{**context, "utxo_heights": [3]})
                    changed_verifier = replace(payment, inputs=(Input(alternate_parent.txid_wire(), 0),
                                                                 *payment.inputs[1:]))
                    funding = (alternate_parent, *parents[1:])
                    with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                        validate_at_heights(build(changed_verifier, funding, alternate_statement), funding, **context)
                for index in (0, 1):
                    substitute = replace(parents[index], outputs=(Output(1000, asm("OP_1")),))
                    funding = (*parents[:index], substitute, *parents[index + 1:])
                    changed = replace(payment, inputs=(
                        *payment.inputs[:index], Input(substitute.txid_wire(), 0), *payment.inputs[index + 1:],
                    ))
                    with self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                        validate_at_heights(build(changed, funding), funding, **context)

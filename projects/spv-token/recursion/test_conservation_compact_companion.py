from dataclasses import replace
from importlib.util import find_spec
import unittest

from conservation_compact_companion import companion_lock, companion_parent_material, companion_witness
from conservation_probe import lock, receipt_output, token_witness
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, blob, preimage_all
from statement_receipt import statement_script, verifier_material
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from transfer import compact_verifier_binding


@unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
class CompactConservationCompanionTests(unittest.TestCase):
    shape = dict(input_count=4, verifier_index=0, preceding_outputs=2)

    def setUp(self):
        # Pad only the proof stand-in, to exercise lossless reuse of a large
        # same-policy field at the size of the native Groth16 verifier.
        self.verifier = (
            asm("OP_0 OP_IF") + push(b"v" * 450_000) + asm("OP_ENDIF")
            + statement_script(**self.shape) + asm("OP_2DROP OP_1") + compact_verifier_binding()
        )
        self.companion = companion_lock(self.verifier)
        self.holders = tuple(fixture_signer(key) for key in (11, 12))
        self.outputs = tuple(
            Output(1000, lock(TokenState(b"a" * 32, 640 - index, holder), companion_lock=self.companion))
            for index, (holder, _) in enumerate(self.holders)
        )
        self.parents = tuple((self.fund(index + 1, output), 0) for index, output in enumerate(self.outputs))

    @staticmethod
    def fund(tag, output):
        return Transaction((Input(bytes([tag]) * 32, 0),), (output,))

    def fixture(self, parents, step=0, *, alternative_verifier=None):
        verifier = self.fund(10 + step * 2, Output(100_000, alternative_verifier or self.verifier))
        companion = self.fund(11 + step * 2, Output(10_000, self.companion))
        previous = tuple(parent.outputs[vout] for parent, vout in parents)
        draft = Transaction((Input(verifier.txid_wire(), 0), Input(companion.txid_wire(), 0),
                             *(Input(parent.txid_wire(), vout) for parent, vout in parents)), self.outputs)
        draft = replace(draft, outputs=(*self.outputs, receipt_output(draft, previous)))
        signed = draft.with_script(0, verifier_material(draft, verifier, **self.shape))
        for index, (_, signer) in enumerate(self.holders, 2):
            signed = signed.with_script(index, token_witness(draft, index, previous, companion, signer))
        return signed, verifier, companion

    def check(self, signed, verifier, companion, parents):
        from shared.chain_gang import validate_at_heights

        direct = {parent.txid_wire(): parent for parent, _ in parents}
        validate_at_heights(signed, (verifier, companion, *direct.values()), spend_height=100,
                            activation_height=2, utxo_heights=(3,) * 4)

    def test_repeated_same_policy_transfers_carry_one_verifier_field(self):
        parents = self.parents
        sizes = []
        for step in range(4):
            signed, verifier, companion = self.fixture(parents, step)
            witness = companion_witness(signed, verifier, companion, parents)
            signed = signed.with_script(1, witness)
            self.check(signed, verifier, companion, parents)
            record = companion_parent_material(self.verifier, self.companion, parents)
            self.assertTrue(witness.startswith(record))
            self.assertEqual(signed.serialize().count(blob(self.verifier)), 1)
            if step:
                self.assertLess(len(record), len(parents[0][0].serialize()) - 400_000)
            sizes.append(len(signed.serialize()))
            parents = ((signed, 0), (signed, 1))
        for growth in (sizes[2] - sizes[1], sizes[3] - sizes[2]):
            self.assertGreater(growth, 0)
            self.assertLess(growth, 30_000)

    def test_decodes_two_distinct_same_policy_payment_parents(self):
        other_origins = tuple((self.fund(index + 3, output), 0) for index, output in enumerate(self.outputs))
        payments = []
        for step, origins in enumerate((self.parents, other_origins)):
            tx, verifier, companion = self.fixture(origins, step)
            tx = tx.with_script(1, companion_witness(tx, verifier, companion, origins))
            self.check(tx, verifier, companion, origins)
            payments.append(tx)

        parents = tuple((payment, index) for index, payment in enumerate(payments))
        tx, verifier, companion = self.fixture(parents, 2)
        tx = tx.with_script(1, companion_witness(tx, verifier, companion, parents))
        self.check(tx, verifier, companion, parents)
        material = companion_parent_material(self.verifier, self.companion, parents)
        self.assertLess(len(material), sum(len(payment.serialize()) for payment in payments) - 800_000)

    def force_companion(self, tx, funding, companion, supplied_parents, *, forced_funding=None):
        records = companion_parent_material(self.verifier, self.companion, supplied_parents)
        prevouts = b"".join(item.outpoint() for item in tx.inputs)
        preimage = preimage_all(tx, 1, companion.outputs[0].value, self.companion)
        return tx.with_script(1, records + b"".join(map(push, (
            (forced_funding or funding).serialize(), prevouts, preimage,
        ))))

    def test_rejects_different_parent_and_verifier_bytes(self):
        tx, funding, companion = self.fixture(self.parents)
        changed_parent = replace(self.parents[0][0], locktime=1)
        changed_funding = replace(funding, locktime=1)
        variants = (
            self.force_companion(tx, funding, companion, ((changed_parent, 0), self.parents[1])),
            self.force_companion(tx, funding, companion, self.parents[::-1]),
            self.force_companion(tx, funding, companion, (self.parents[0], self.parents[0])),
            self.force_companion(tx, funding, companion, self.parents, forced_funding=changed_funding),
        )
        for bad in variants:
            with self.assertRaises(ValueError):
                self.check(bad, funding, companion, self.parents)

        # Change the actual funded verifier. Recompute the receipt and all
        # signatures so only the companion's exact verifier pin rejects it.
        tx, other, companion = self.fixture(self.parents, alternative_verifier=asm("OP_NOP") + self.verifier)
        bad = self.force_companion(tx, other, companion, self.parents)
        with self.assertRaises(ValueError):
            self.check(bad, other, companion, self.parents)

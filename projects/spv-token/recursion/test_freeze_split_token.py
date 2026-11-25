from dataclasses import replace
from importlib.util import find_spec
import unittest

import freeze_probe
import freeze_split_token as split
from shared.evaluate import evaluate
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_forkid
from statement_receipt import receipt_digest, receipt_output
from test_operational_token import fixture_signer
from transaction_relation import TokenState


class FreezeSplitTokenTests(unittest.TestCase):
    def setUp(self):
        self.issuer, self.sign = fixture_signer(12)
        owner, _ = fixture_signer(11)
        self.state = TokenState(b"a" * 32, 640, owner)
        # A stand-in verifier lets these tests focus on the token shell's native input rules.
        self.approved = asm("OP_1")
        self.funding = Transaction((Input(b"f" * 32, 0),), (Output(500_000, self.approved),))
        self.parent = Transaction((Input(b"p" * 32, 0),), (Output(1000, split.lock(self.state, self.issuer, self.approved)),))

    def candidate(self, parent=None, funding=None, *, funding_vout=0):
        parent = self.parent if parent is None else parent
        funding = self.funding if funding is None else funding
        previous = parent.outputs[0]
        tx = Transaction((Input(parent.txid_wire(), 0, sequence=101), Input(funding.txid_wire(), funding_vout, sequence=102)),
                         (split.paired_successor(previous),), version=1, locktime=3)
        return replace(tx, outputs=tx.outputs + (split.receipt_output(tx, previous),))

    def raw_witness(self, tx, *, funding=None, index=0, outputs=None, signer=None):
        """Assemble a signed malformed candidate without the checked wallet helper."""
        previous = self.parent.outputs[0]
        funding = self.funding if funding is None else funding
        signer = self.sign if signer is None else signer
        paired, receipt = tx.outputs[:2] if outputs is None else outputs
        paired = paired if isinstance(paired, bytes) else paired.serialize()
        full = preimage_forkid(tx, index, previous.value, previous.script, freeze_probe.ALL)
        return b"".join(map(push, (
            signer(hash256(full)) + bytes([freeze_probe.ALL]), funding.serialize(),
            b"".join(vin.outpoint() for vin in tx.inputs), paired, receipt.serialize(), full,
        )))

    def test_synthetic_single_and_wire_match_the_existing_proof_statement(self):
        tx = self.candidate()
        previous = self.parent.outputs[0]
        for candidate in (tx, replace(tx, version=2, locktime=7),
                          replace(tx, outputs=(replace(tx.outputs[0], value=1001), tx.outputs[1]))):
            all_preimage = preimage_forkid(candidate, 0, previous.value, previous.script, freeze_probe.ALL)
            single = hash256(preimage_forkid(candidate, 0, previous.value, previous.script, freeze_probe.SINGLE))
            paired = candidate.outputs[0].serialize()
            self.assertEqual(evaluate(split._single_digest(), stack=[paired, all_preimage]), ([paired, all_preimage, single], []))
        skeleton = replace(tx, outputs=tx.outputs[:1])
        statement = freeze_probe.statement(skeleton, previous)
        self.assertEqual(split.statement(tx, previous), statement)
        self.assertEqual(receipt_digest(tx.outputs[1]), hash256(statement))

    def test_wallet_signs_the_exact_all_preimage_and_checks_receipt_before_signing(self):
        tx = self.candidate()
        previous = self.parent.outputs[0]
        signed = []

        def capture(digest):
            signed.append(digest)
            return self.sign(digest)

        witness = split.transaction_witness(tx, previous, self.funding, capture)
        self.assertEqual(witness, self.raw_witness(tx))
        self.assertEqual(signed, [hash256(preimage_forkid(tx, 0, previous.value, previous.script, freeze_probe.ALL))])
        wrong = replace(tx, outputs=(tx.outputs[0], receipt_output(bytes(32))))
        with self.assertRaisesRegex(ValueError, "exact statement receipt"):
            split.transaction_witness(wrong, previous, self.funding, capture)
        self.assertEqual(len(signed), 1)

    @unittest.skipUnless(find_spec("tx_engine"), "requires the independent chain-gang evaluator")
    def test_real_inputs_accept_freeze_then_unfreeze(self):
        from shared.chain_gang import validate_at_heights

        funding = self.funding
        parent = self.parent
        lock = parent.outputs[0].script
        for _ in range(2):
            tx = self.candidate(parent, funding)
            witness = split.transaction_witness(tx, parent.outputs[0], funding, self.sign)
            tx = tx.with_script(0, witness)
            validate_at_heights(tx, (parent, funding), spend_height=10, activation_height=2, utxo_heights=(3, 3))
            parent = tx
            funding = replace(funding, inputs=(replace(funding.inputs[0], vout=1),))
        self.assertEqual(parent.outputs[0].script, lock)

    @unittest.skipUnless(find_spec("tx_engine"), "requires the independent chain-gang evaluator")
    def test_rejects_changed_receipts_outputs_roles_and_funding(self):
        from shared.chain_gang import validate_at_heights

        base = self.candidate()
        pair, receipt = base.outputs
        changed = replace(pair, value=1001)
        wrong_guard = replace(self.funding, outputs=(Output(500_000, asm("OP_2 OP_DROP OP_1")),))
        wrong_shape = replace(self.funding, outputs=self.funding.outputs * 2)
        unbound = replace(self.funding, locktime=1)
        wrong_position = replace(base, inputs=base.inputs[::-1])
        extra = Output(100, self.approved)
        cases = {
            "new receipt payload": (replace(base, outputs=(pair, receipt_output(bytes(32)))), self.funding, {}, 0),
            "nonzero receipt": (replace(base, outputs=(pair, replace(receipt, value=1))), self.funding, {}, 0),
            "trailing receipt script": (replace(base, outputs=(pair, replace(receipt, script=receipt.script + b"\x51"))), self.funding, {}, 0),
            "paired value changed with old receipt": (replace(base, outputs=(changed, receipt)), self.funding, {}, 0),
            "extra actual output": (replace(base, outputs=(*base.outputs, extra)), self.funding, {}, 0),
            "extra output disguised inside paired blob": (replace(base, outputs=(pair, extra, receipt)), self.funding,
                {"outputs": (pair.serialize() + extra.serialize(), receipt)}, 0),
            "wrong role": (base, self.funding, {"signer": fixture_signer(13)[1]}, 0),
            "wrong actual verifier": (self.candidate(funding=wrong_guard), wrong_guard, {}, 0),
            "wrong verifier vout": (self.candidate(funding=wrong_shape, funding_vout=1), wrong_shape, {}, 0),
            "provided funding not actually consumed": (base, self.funding, {"funding": unbound}, 0),
            "token at actual vin 1": (wrong_position, self.funding, {"index": 1}, 1),
        }
        for label, (tx, funding, overrides, index) in cases.items():
            material = self.raw_witness(tx, **{"funding": funding, **overrides})
            with self.subTest(case=label), self.assertRaisesRegex((ValueError, RuntimeError), "Error evaluating the script"):
                validate_at_heights(tx.with_script(index, material), (self.parent, funding),
                                    spend_height=10, activation_height=2, utxo_heights=(3, 3))


if __name__ == "__main__":
    unittest.main()

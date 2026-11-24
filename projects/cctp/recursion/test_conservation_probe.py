from dataclasses import replace
from hashlib import sha256
from importlib.util import find_spec
import unittest

import conservation_probe as probe
from shared.evaluate import evaluate, ScriptError
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_forkid
from statement_receipt import receipt_digest, receipt_output
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from transfer import shared_guard_lock


class ConservationProbeTests(unittest.TestCase):
    def setUp(self):
        keys_and_signers = tuple(fixture_signer(secret) for secret in (11, 12, 13, 14))
        self.owners = tuple(key for key, _ in keys_and_signers)
        self.signers = tuple(sign for _, sign in keys_and_signers)
        self.verifier_lock = asm("OP_1")
        self.verifier = self.fund(5, Output(100_000, self.verifier_lock))
        self.companion = self.fund(6, Output(20_000, shared_guard_lock(self.verifier_lock)))
        self.priors = tuple(self.token(quantity, owner, sats) for quantity, owner, sats in
                            zip((640, 384), self.owners[:2], (3000, 4000), strict=True))
        self.parents = (self.verifier, self.companion, self.fund(7, self.priors[0]), self.fund(8, self.priors[1]))
        self.successors = tuple(self.token(quantity, owner, 3500) for quantity, owner in
                                zip((700, 324), self.owners[2:], strict=True))
        self.skeleton = self.candidate(self.parents)
        self.tx = self.add_receipt(self.skeleton)

    @staticmethod
    def fund(tag, output):
        return Transaction((Input(bytes([tag]) * 32, 0),), (output,))

    def token(self, quantity, owner, sats):
        return Output(sats, probe.lock(TokenState(b"a" * 32, quantity, owner), self.verifier_lock))

    def candidate(self, parents):
        inputs = tuple(Input(parent.txid_wire(), 0, sequence=10 + i) for i, parent in enumerate(parents))
        return Transaction(inputs, self.successors, version=1, locktime=3)

    def add_receipt(self, candidate):
        return replace(candidate, outputs=(*candidate.outputs, probe.receipt_output(candidate, self.priors)))

    def raw_witness(self, tx, index, *, companion=None, records=None, signer=None):
        companion = self.companion if companion is None else companion
        signer = self.signers[index - 2] if signer is None else signer
        if records is None:
            records = b"".join(probe.state_record(output) for output in self.priors)
        spent = self.priors[index - 2]
        preimage = preimage_forkid(tx, index, spent.value, spent.script, probe.ALL)
        return b"".join(map(push, (
            signer(hash256(preimage)) + bytes([probe.ALL]), companion.serialize(), probe._prevouts(tx),
            records, b"".join(output.serialize() for output in tx.outputs), preimage,
        )))

    def sign(self, tx, companion=None, *, token2=None, token3=None):
        companion = self.companion if companion is None else companion
        spent = companion.outputs[0]
        preimage = preimage_forkid(tx, 1, spent.value, spent.script, probe.ALL)
        carrier = push(self.verifier.serialize()) + push(probe._prevouts(tx)) + push(preimage)
        if token2 is None:
            token2 = self.raw_witness(tx, 2, companion=companion)
        if token3 is None:
            token3 = self.raw_witness(tx, 3, companion=companion)
        return tx.with_script(1, carrier).with_script(2, token2).with_script(3, token3)

    def test_exact_context_records_and_normalized_policy(self):
        expected = (
            b"\x01\x00\x00\x00" + hash256(b"".join(vin.outpoint() for vin in self.tx.inputs))
            + hash256(b"".join(sequence.to_bytes(4, "little") for sequence in range(10, 14)))
            + hash256(b"".join(output.serialize() for output in self.successors)) + b"\x03\x00\x00\x00"
        )
        proof_wire = probe.statement(self.skeleton, self.priors)
        self.assertEqual(len(proof_wire), 585)
        self.assertEqual(probe.statement(self.tx, self.priors), proof_wire)
        self.assertEqual(receipt_digest(self.tx.outputs[2]), hash256(proof_wire))
        payload = proof_wire[len(probe.DOMAIN):]
        self.assertEqual(payload[:104], expected)
        records = payload[104:]
        self.assertEqual(len(records), 4 * 114)
        for index, output in enumerate((*self.priors, *self.successors)):
            record = records[index * 114:(index + 1) * 114]
            meta = len(probe.METADATA_PREFIX)
            normalized = output.script[:meta] + bytes(74) + output.script[meta + 74:]
            self.assertEqual(record[:8], output.value.to_bytes(8, "little"))
            self.assertEqual(record[48:81], self.owners[index])
            self.assertEqual(record[-32:], sha256(blob(normalized)).digest())
            self.assertEqual(record[-32:], records[82:114])
            self.assertEqual(output.script.count(self.owners[index]), 1)

        record_script = push(b"kept alt") + asm("OP_TOALTSTACK") + probe.state_record_script()
        for output in (*self.priors, *self.successors):
            amount = output.value.to_bytes(8, "little")
            field = blob(output.script)
            self.assertEqual(evaluate(record_script, stack=[b"kept", amount, field]),
                             ([b"kept", probe.state_record(output)], [b"kept alt"]))
            with self.assertRaises(ScriptError):
                evaluate(record_script, stack=[b"kept", amount, field + b"\x00"])

    def test_each_vin_checks_its_own_record_against_the_common_receipt(self):
        first, second = tuple(map(probe.state_record, self.priors))
        invented = bytearray(second)
        invented[0] ^= 1
        records = first + invented
        wire = probe.statement(self.skeleton, self.priors)
        offset = len(probe.DOMAIN) + probe.CONTEXT_SIZE
        forged_wire = wire[:offset] + records + wire[offset + 2 * probe.STATE_SIZE:]
        tx = replace(self.tx, outputs=(*self.successors, receipt_output(hash256(forged_wire))))
        for index in (2, 3):
            material = self.raw_witness(tx, index, records=records)
            lock = self.priors[index - 2].script
            if index == 2:
                self.assertEqual(evaluate(material + lock, checksig=lambda *_: True), ([b"\x01"], []))
            else:
                with self.assertRaises(ScriptError):
                    evaluate(material + lock, checksig=lambda *_: True)

    @unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
    def test_chain_gang_binds_real_companion_and_both_real_holder_inputs(self):
        from shared.chain_gang import validate_at_heights

        material = tuple(probe.token_witness(self.tx, index, self.priors, self.companion, self.signers[index - 2])
                         for index in (2, 3))
        self.assertEqual(material, tuple(self.raw_witness(self.tx, index) for index in (2, 3)))
        final = self.sign(self.tx, token2=material[0], token3=material[1])
        heights = {"spend_height": 10, "activation_height": 2, "utxo_heights": (3,) * 4}
        validate_at_heights(final, self.parents, **heights)

        old_receipt = self.tx.outputs[2]
        wrong_output = replace(self.tx, outputs=(replace(self.tx.outputs[0], value=3510), self.tx.outputs[1], old_receipt))
        extra = replace(self.tx, outputs=(*self.successors, Output(100, self.verifier_lock), old_receipt))
        paid_receipt = replace(self.tx, outputs=(*self.successors, replace(old_receipt, value=1)))
        changed_sequence = replace(self.tx, inputs=(*self.tx.inputs[:3], replace(self.tx.inputs[3], sequence=99)))
        unbound = replace(self.companion, locktime=1)
        alias_lock = asm("OP_1 OP_DROP") + self.companion.outputs[0].script
        alias = replace(self.companion, outputs=(replace(self.companion.outputs[0], script=alias_lock),))
        alternate = (self.parents[0], alias, *self.parents[2:])
        alias_tx = self.add_receipt(self.candidate(alternate))
        cases = {
            "issuer or another holder": (self.sign(self.tx, token2=self.raw_witness(self.tx, 2, signer=self.signers[1])), self.parents),
            "actual paired satoshis changed": (self.sign(wrong_output), self.parents),
            "extra actual vout": (self.sign(extra), self.parents),
            "nonzero receipt price": (self.sign(paid_receipt), self.parents),
            "actual sequence changed": (self.sign(changed_sequence), self.parents),
            "wrong companion parent raw": (self.sign(self.tx, token2=self.raw_witness(self.tx, 2, companion=unbound)), self.parents),
            "actual wrong companion lock": (self.sign(alias_tx, companion=alias), alternate),
        }
        for name, (tx, parents) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex((RuntimeError, ValueError), "Error evaluating the script"):
                validate_at_heights(tx, parents, **heights)


if __name__ == "__main__":
    unittest.main()

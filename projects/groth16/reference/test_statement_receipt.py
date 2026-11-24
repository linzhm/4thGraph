"""Complete-input and canonical framing tests without CCTP dependencies."""

from dataclasses import replace
from importlib.util import find_spec
import unittest

from fixtures import fixture
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, encode_num, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement_receipt import (
    RECEIPT_PREFIX, RECEIPT_SIZE, receipt_digest, receipt_output, statement_script, verifier_lock,
    verifier_material, verifier_witness,
)
from test_bsb22_independent import arithmetic_fixture
from transfer import COMPACT_SCRIPTCODE, COMPACT_SUFFIX


def funding_pair(lock):
    return (
        Transaction((Input(b"t" * 32, 0),), (Output(10_000, asm("OP_1")),)),
        Transaction((Input(b"v" * 32, 0),), (Output(10_000, lock),)),
    )


def spend(parents, out, digest):
    return Transaction((Input(parents[0].txid_wire(), 0, sequence=42), Input(parents[1].txid_wire(), 0)),
                       (out, receipt_output(digest)), locktime=410)


def as_digest(signals):
    return b"".join(item.to_bytes(16, "big") for item in signals)


class StatementReceiptTests(unittest.TestCase):
    def test_script_extracts_exact_two_big_endian_limbs(self):
        parents = funding_pair(COMPACT_SUFFIX)
        signals = (2**128 - 1, 2**127 + 5)
        digest = as_digest(signals)
        receipt = receipt_output(digest)
        self.assertEqual(receipt.serialize(), RECEIPT_PREFIX + digest)
        self.assertEqual(RECEIPT_SIZE, len(receipt.serialize()))
        self.assertEqual(digest, receipt_digest(receipt))
        for script in (b"", b"\x51", b"x" * 253, b"y" * 65536, receipt.serialize()):
            with self.subTest(script_bytes=len(script)):
                tx = spend(parents, Output(900, script), digest)
                result = evaluate(verifier_material(tx, parents[1]) + statement_script(),
                                  [b"proof fields"])
                context = hash256(preimage_all(tx, 1, parents[1].outputs[0].value, COMPACT_SCRIPTCODE))
                self.assertEqual(result, ([b"proof fields", *map(encode_num, signals)], [context]))

    def test_script_rejects_malformed_framing_even_with_matching_hashes(self):
        parents = funding_pair(COMPACT_SUFFIX)
        digest = as_digest((16, 55))
        tx = spend(parents, Output(900, b"\x51"), digest)
        paired, receipt = tx.outputs
        prevouts = b"".join(item.outpoint() for item in tx.inputs)
        base = preimage_all(tx, 1, parents[1].outputs[0].value, COMPACT_SCRIPTCODE)
        outputs = paired.serialize() + receipt.serialize()

        def reject(outputs=outputs, prevouts=prevouts, preimage=base):
            # Replace both component hashes so a malformed shape cannot just
            # fail an earlier hash equality.
            actual = preimage[:4] + hash256(prevouts) + preimage[36:152] + hash256(outputs) + preimage[184:]
            with self.assertRaises(ScriptError):
                evaluate(b"".join(map(push, (outputs, prevouts, actual))) + statement_script())

        for malformed in (
            outputs + paired.serialize(),
            paired.serialize(),
            receipt.serialize() + paired.serialize(),
            paired.serialize() + replace(receipt, value=1).serialize(),
            paired.serialize() + replace(receipt, script=receipt.script + b"\x01").serialize(),
            paired.serialize() + replace(receipt, script=receipt.script[:-1]).serialize(),
            paired.serialize()[:8] + b"\xfd\x01\x00\x51" + receipt.serialize(),
            paired.serialize() + receipt.serialize()[:8] + b"\xfd" + bytes([len(receipt.script), 0]) + receipt.script,
        ):
            reject(outputs=malformed)
        reject(prevouts=prevouts[36:] + prevouts[:36])
        reject(prevouts=prevouts + prevouts[:36])
        reject(preimage=base[:105] + b"\x51" + base[106:])
        reject(preimage=base[:-4] + b"\x43" + bytes(3))

    @unittest.skipUnless(find_spec("tx_engine"), "requires the independent chain-gang evaluator")
    def test_plain_and_independent_bsb22_proof_spends(self):
        from shared.chain_gang import validate_at_heights

        plain_key, plain_signals, plain_proof = fixture()
        key, relation, signals, proof = arithmetic_fixture()
        self.assertEqual(signals, (16, 55))
        for vk, commitment, public, proof in (
            (plain_key, None, plain_signals, plain_proof), (key, relation, signals, proof),
        ):
            with self.subTest(committed=commitment is not None):
                parents = funding_pair(verifier_lock(vk, commitment))
                tx = spend(parents, Output(900, asm("OP_1")), as_digest(public))
                material = verifier_material(tx, parents[1])
                witness = verifier_witness(vk, proof, tx, parents[1], commitment)
                signed = tx.with_script(1, witness)
                context = dict(spend_height=100, activation_height=2, utxo_heights=(3, 3))
                validate_at_heights(signed, parents, **context)

                # Updating the actual tx without refreshing its preimage fails
                # CHECKSIG, even though the receipt and proof are unchanged.
                changed_output = replace(signed, outputs=(replace(tx.outputs[0], value=901), tx.outputs[1]))
                with self.assertRaises(ValueError):
                    validate_at_heights(changed_output, parents, **context)

                wrong_receipt = replace(tx, outputs=(tx.outputs[0], receipt_output(as_digest((public[0], public[1]+1)))))
                updated = verifier_material(wrong_receipt, parents[1])
                with self.assertRaises(ValueError):
                    validate_at_heights(wrong_receipt.with_script(1, witness[:-len(material)] + updated),
                                        parents, **context)

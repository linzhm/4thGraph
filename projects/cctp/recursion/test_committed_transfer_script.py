from dataclasses import replace
from importlib.util import find_spec
import unittest

from chronicle_context_script import bind_all_context
from chronicle_preimage import CHRONICLE_ALL, VERIFIER_SEQUENCES
from committed_transfer_script import statement_script
from continuity_statement import CommittedParentReceipt
from shared.evaluate import evaluate
from shared.script import asm, encode_num, number, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_otda
from transfer import COMPACT_SCRIPTCODE

ASSET = hash256(b"committed transfer fixture asset")
SELF_KEY = hash256(b"committed transfer fixture key")
PRIOR_DIGESTS = tuple(hash256(bytes([n])) for n in range(4))


def fixture(token_inputs, token_outputs):
    statement = statement_script(ASSET, SELF_KEY, token_inputs=token_inputs, token_outputs=token_outputs)
    # Compare the derived limbs to host values in place of a Groth16 verifier.
    lock = statement + asm("OP_ROT OP_NUMEQUALVERIFY OP_NUMEQUAL") + bind_all_context()
    parents = tuple(Transaction((Input(hash256(bytes([i])), 0),), (Output(10_000, output),))
                    for i, output in enumerate([lock] + [asm("OP_1")] * token_inputs))
    inputs = tuple(Input(parent.txid_wire(), 0, sequence=VERIFIER_SEQUENCES[CHRONICLE_ALL] if i == 0 else 0xffffffff)
                   for i, parent in enumerate(parents))
    receipt = CommittedParentReceipt.from_parents(PRIOR_DIGESTS[:token_inputs])
    outputs = tuple(Output(100 + i, asm("OP_1") if i else b"\x51" * 253) for i in range(token_outputs))
    return statement, Transaction(inputs, outputs + (receipt.output(),)), parents, receipt


def preimage(tx):
    return preimage_otda(tx, 0, COMPACT_SCRIPTCODE, CHRONICLE_ALL)


def signals(receipt, raw):
    digest = receipt.digest(ASSET, SELF_KEY, hash256(raw))
    return int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")


class CommittedTransferScriptTests(unittest.TestCase):
    def test_extracts_host_statement_and_preserves_binding_context(self):
        for shape in ((1, 4), (2, 1), (3, 2), (4, 4)):
            with self.subTest(shape=shape):
                statement, tx, _, receipt = fixture(*shape)
                raw = preimage(tx)
                high, low = signals(receipt, raw)
                outer = push(b"caller") + asm("OP_TOALTSTACK")
                self.assertEqual(evaluate(outer + statement, [b"proof fields", raw]),
                                 ([b"proof fields", encode_num(high), encode_num(low)],
                                  [b"caller", bytes([CHRONICLE_ALL]), hash256(raw)]))

    @unittest.skipUnless(find_spec("tx_engine"), "requires the independent chain-gang evaluator")
    def test_binds_actual_transaction_and_rejects_wrong_receipt_or_layout(self):
        from shared.chain_gang import validate_at_heights

        def validate(tx, parents, receipt, *, raw=None, verifier_index=0):
            raw = preimage(tx) if raw is None else raw
            high, low = signals(receipt, raw)
            witness = number(high) + number(low) + push(raw)
            validate_at_heights(tx.with_script(verifier_index, witness), parents, spend_height=4,
                                activation_height=3, utxo_heights=[3] * len(tx.inputs))

        for shape in ((1, 4), (4, 4)):
            _, tx, parents, receipt = fixture(*shape)
            with self.subTest(shape=shape):
                validate(tx, parents, receipt)

        _, tx, parents, receipt = fixture(4, 4)
        wrong_count = CommittedParentReceipt.from_parents(PRIOR_DIGESTS[:3])
        last, preceding = tx.outputs[-1], tx.outputs[:-1]
        verifier_at_vin_one = replace(tx, inputs=(replace(tx.inputs[1], sequence=tx.inputs[0].sequence),
                                                  tx.inputs[0], *tx.inputs[2:]))
        for label, transaction, funds, supplied, options in (
            ("receipt count", replace(tx, outputs=preceding + (wrong_count.output(),)), parents, wrong_count, {}),
            ("receipt value", replace(tx, outputs=preceding + (replace(last, value=1),)), parents, receipt, {}),
            ("receipt marker", replace(tx, outputs=preceding + (Output(0, b"\x51" + last.script[1:]),)),
             parents, receipt, {}),
            ("receipt as a suffix", replace(tx, outputs=preceding + (Output(0, push(last.serialize())),)),
             parents, receipt, {}),
            ("extra output", replace(tx, outputs=preceding + (preceding[0], last)), parents, receipt, {}),
            ("missing input", replace(tx, inputs=tx.inputs[:-1]), parents[:-1], receipt, {}),
            ("wrong sequence", replace(tx, inputs=(replace(tx.inputs[0], sequence=0xffffffff), *tx.inputs[1:])),
             parents, receipt, {}),
            ("wrong verifier vin", verifier_at_vin_one, (parents[1], parents[0], *parents[2:]), receipt,
             {"verifier_index": 1}),
            ("stale preimage", replace(tx, locktime=1), parents, receipt, {"raw": preimage(tx)}),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "Error evaluating the script"):
                validate(transaction, funds, supplied, **options)

    def test_rejects_invalid_profile(self):
        for shape in ((0, 1), (1, 0), (5, 1), (1, 5), (True, 1)):
            with self.subTest(shape=shape), self.assertRaises(ValueError):
                statement_script(ASSET, SELF_KEY, token_inputs=shape[0], token_outputs=shape[1])
        for asset, key in ((ASSET[:-1], SELF_KEY), (ASSET, SELF_KEY + b"\x00")):
            with self.assertRaises(ValueError):
                statement_script(asset, key, token_inputs=1, token_outputs=4)

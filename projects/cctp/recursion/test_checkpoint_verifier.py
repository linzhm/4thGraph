from dataclasses import replace
from importlib.util import find_spec
import unittest

import checkpoint_verifier as checkpoint
from parent_prefix import parent_prefix
from shared.evaluate import evaluate, ScriptError
from shared.script import asm, encode_num, number, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import public_inputs
from transfer import COMPACT_SCRIPTCODE, compact_verifier_binding


class CheckpointVerifierTests(unittest.TestCase):
    def setUp(self):
        self.wanted = Output(1000, asm("OP_1"))
        self.other = Output(2000, asm("OP_1"))
        self.parent = Transaction((Input(b"p" * 32, 1, push(b"a" * 256)),), (self.wanted, self.other))
        self.raw = self.parent.serialize()
        self.checkpoint = parent_prefix(self.raw)
        self.state = self.checkpoint.state
        self.suffix = self.checkpoint.suffix
        self.statement = checkpoint.statement_bytes(self.parent.txid_wire(), self.state, self.suffix)
        self.signals = public_inputs(self.statement)

    def verifier_funding(self, *, required_output=None):
        high, low = self.signals
        # A fixed-limb check stands in for Groth16 in a native binding test.
        proof = number(low) + asm("OP_NUMEQUALVERIFY") + number(high) + asm("OP_NUMEQUAL")
        lock = checkpoint.statement_script(required_output=required_output) + proof + compact_verifier_binding()
        return Transaction((Input(b"v" * 32, 1),), (Output(10_000, lock),))

    def spending(self, funding, *, parent=None, vout=0):
        parent = self.parent if parent is None else parent
        return Transaction((Input(parent.txid_wire(), vout, sequence=1), Input(funding.txid_wire(), 0, sequence=2)),
                           (Output(500, asm("OP_1")),))

    def raw_material(self, tx, funding, *, state=None, suffix=None, index=1, prevouts=None):
        state = self.state if state is None else state
        suffix = self.suffix if suffix is None else suffix
        preimage = preimage_all(tx, index, funding.outputs[0].value, COMPACT_SCRIPTCODE)
        prevouts = b"".join(vin.outpoint() for vin in tx.inputs) if prevouts is None else prevouts
        return b"".join(map(push, (state, suffix, prevouts, preimage)))

    def test_exact_public_message_and_deferred_actual_preimage_binding(self):
        self.assertEqual(len(self.raw), 332)
        self.assertEqual(self.checkpoint.processed_bytes, 256)
        self.assertEqual(self.checkpoint.output_count_offset, 307)
        expected = (b"BSV/CCTP/parent-checkpoint/v1\x00" + hash256(self.raw) + self.state
                    + (256).to_bytes(8, "little") + (307).to_bytes(4, "little") + (2).to_bytes(4, "little")
                    + hash256(self.raw[256:]) + hash256(self.raw[308:328]))
        self.assertEqual(self.statement, expected)
        funding = self.verifier_funding(required_output=self.wanted)
        tx = self.spending(funding)
        material = checkpoint.verifier_material(tx, funding, self.state, self.suffix)
        self.assertEqual(material, self.raw_material(tx, funding))
        auth = hash256(preimage_all(tx, 1, funding.outputs[0].value, COMPACT_SCRIPTCODE))
        script = push(b"proof fields") + material + checkpoint.statement_script(required_output=self.wanted)
        self.assertEqual(evaluate(script), ([b"proof fields", *map(encode_num, self.signals)], [auth]))

    def test_rejects_invalid_profile_and_actual_vin_or_vout_shapes(self):
        funding = self.verifier_funding(required_output=self.wanted)
        tx = self.spending(funding)
        suffix = self.suffix
        for invalid in (suffix[:-1], suffix[:51] + b"\x03" + suffix[52:], suffix[:60] + b"\x02" + suffix[61:]):
            with self.subTest(suffix=invalid.hex()), self.assertRaises(ValueError):
                checkpoint.statement_bytes(self.parent.txid_wire(), self.state, invalid)
            with self.subTest(suffix=invalid.hex()), self.assertRaises(ScriptError):
                evaluate(self.raw_material(tx, funding, suffix=invalid) + checkpoint.statement_script())
        for position in (2, 0x80000000, 0xFFFFFFFF):
            with self.subTest(position=position), self.assertRaises(ScriptError):
                bad = self.spending(funding, vout=position)
                evaluate(self.raw_material(bad, funding) + checkpoint.statement_script())
        for material in (self.raw_material(tx, funding, state=bytes(31)),
                         self.raw_material(tx, funding, prevouts=bytes(72)),
                         self.raw_material(replace(tx, inputs=tx.inputs[::-1]), funding, index=0),
                         self.raw_material(self.spending(funding, vout=1), funding)):
            with self.assertRaises(ScriptError):
                evaluate(material + checkpoint.statement_script(required_output=self.wanted))

    @unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
    def test_native_input_binding_and_optional_exact_target_without_new_proof(self):
        from shared.chain_gang import validate_at_heights

        context = {"spend_height": 10, "activation_height": 2, "utxo_heights": (3, 3)}
        for required_output in (None, self.wanted):
            funding = self.verifier_funding(required_output=required_output)
            for index in (0, 1):
                tx = self.spending(funding, vout=index)
                material = checkpoint.verifier_material(tx, funding, self.state, self.suffix)
                signed = tx.with_script(1, material)
                with self.subTest(required_output=required_output, vout=index):
                    if required_output is None or index == 0:
                        validate_at_heights(signed, (self.parent, funding), **context)
                    else:
                        with self.assertRaisesRegex((ValueError, RuntimeError), "Error evaluating the script"):
                            validate_at_heights(signed, (self.parent, funding), **context)

        funding = self.verifier_funding(required_output=self.wanted)
        tx = self.spending(funding)
        mutated_parent = replace(self.parent, locktime=1)
        wrong_parent = self.spending(funding, parent=mutated_parent)
        candidates = (
            (tx.with_script(1, self.raw_material(tx, funding, state=bytes(32))), self.parent),
            (tx.with_script(1, self.raw_material(tx, funding, suffix=b"\xff" + self.suffix[1:])), self.parent),
            (wrong_parent.with_script(1, self.raw_material(wrong_parent, funding)), mutated_parent),
            (replace(tx.with_script(1, self.raw_material(tx, funding)), outputs=(Output(900, asm("OP_1")),)), self.parent),
        )
        for bad, parent in candidates:
            with self.subTest(txid=bad.txid()), self.assertRaisesRegex((ValueError, RuntimeError), "Error evaluating the script"):
                validate_at_heights(bad, (parent, funding), **context)


if __name__ == "__main__":
    unittest.main()

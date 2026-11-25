from dataclasses import replace
from hashlib import sha256
from importlib.util import find_spec
import unittest

from chronicle_preimage_script import MAX_INPUTS, MAX_OUTPUTS, otda_all_fields
from shared.evaluate import ScriptError, evaluate
from shared.pushtx import binding_der
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, blob, compact, hash256, preimage_otda
from transfer import COMPACT_SCRIPTCODE, COMPACT_SUFFIX


def make_transaction(input_count, output_count, *, version=2):
    inputs = tuple(Input(hash256(i.to_bytes(2, "little")), i + 7, b"real unlocking script",
                         sequence=0xffffffff - 123 * i) for i in range(input_count))
    outputs = tuple(Output(i * 173, (b"\x51" * (i % 5))) for i in range(output_count))
    return Transaction(inputs, outputs, version=version, locktime=0x81726354)


class ChroniclePreimageScriptTests(unittest.TestCase):
    def assert_fields(self, tx, verifier_index, script_code=COMPACT_SCRIPTCODE):
        raw = preimage_otda(tx, verifier_index, script_code, 0x61)
        code = otda_all_fields(len(tx.inputs), len(tx.outputs), verifier_index, script_code=script_code)
        expected = [
            tx.version.to_bytes(4, "little"),
            b"".join(item.outpoint() for item in tx.inputs),
            b"".join(item.sequence.to_bytes(4, "little") for item in tx.inputs),
            tx.inputs[verifier_index].outpoint(),
            tx.inputs[verifier_index].sequence.to_bytes(4, "little"),
            b"".join(item.serialize() for item in tx.outputs),
            tx.locktime.to_bytes(4, "little"),
        ]
        prefix = push(b"caller altstack") + asm("OP_TOALTSTACK")
        self.assertEqual(evaluate(prefix + code, [b"caller stack", raw, raw]),
                         ([b"caller stack", raw, *expected], [b"caller altstack"]))

    def test_narrow_versions_and_all_verifier_indices(self):
        self.assert_fields(make_transaction(1, 1, version=1), 0)
        for index in range(4):
            with self.subTest(index=index):
                self.assert_fields(make_transaction(4, 3), index)

    def test_wide_counts_and_compact_size_script_fields(self):
        self.assert_fields(make_transaction(MAX_INPUTS, MAX_OUTPUTS), MAX_INPUTS - 1)
        regular = make_transaction(2, 2)
        sized = Transaction(regular.inputs, (Output(2, b"\x51" * 253), Output(3, b"\x52" * 65536)))
        self.assert_fields(sized, 1, script_code=b"\x51" * 253)

    def test_rejects_malformed_preimage_and_incorrect_script_index(self):
        tx = make_transaction(2, 3)
        raw = preimage_otda(tx, 1, COMPACT_SCRIPTCODE, 0x61)
        code = otda_all_fields(2, 3, 1)
        input_count_at = 4
        first_input_script_at = input_count_at + len(compact(2)) + 36
        output_count_at = input_count_at + len(compact(2)) + 41 * 2 + len(blob(COMPACT_SCRIPTCODE)) - 1
        first_output_script_at = output_count_at + len(compact(3)) + 8
        mutants = {
            "forkid_flag": raw[:-4] + b"\x41\x00\x00\x00",
            "single_flag": raw[:-4] + b"\x63\x00\x00\x00",
            "reserved_flag_bytes": raw[:-1] + b"\x01",
            "wrong_index": preimage_otda(tx, 0, COMPACT_SCRIPTCODE, 0x61),
            "wrong_code": preimage_otda(tx, 1, COMPACT_SCRIPTCODE[:-1] + b"\x51", 0x61),
            "noncanonical_input_count": raw[:input_count_at] + b"\xfd\x02\x00" + raw[input_count_at + 1:],
            "extra_input_script": raw[:first_input_script_at] + b"\x01\x51" + raw[first_input_script_at + 1:],
            "noncanonical_empty_input_field": (
                raw[:first_input_script_at] + b"\xfd\x00\x00" + raw[first_input_script_at + 1:]
            ),
            "noncanonical_output_count": raw[:output_count_at] + b"\xfd\x03\x00" + raw[output_count_at + 1:],
            "noncanonical_output_field": (
                raw[:first_output_script_at] + b"\xfd\x00\x00" + raw[first_output_script_at + 1:]
            ),
            "wrong_output_count": raw[:output_count_at] + b"\x02" + raw[output_count_at + 1:],
            "truncated_output": raw[:-9] + raw[-8:],
            "trailing_output_byte": raw[:-8] + b"\x00" + raw[-8:],
        }
        for label, mutant in mutants.items():
            with self.subTest(label=label), self.assertRaises(ScriptError):
                evaluate(code, [mutant])

    def test_profile_bounds(self):
        for inputs, outputs, index in (
            (0, 1, 0), (MAX_INPUTS + 1, 1, 0), (1, 0, 0),
            (1, MAX_OUTPUTS + 1, 0), (2, 1, 2), (2, 1, -1), (True, 1, 0),
        ):
            with self.subTest(inputs=inputs, outputs=outputs, index=index), self.assertRaises(ValueError):
                otda_all_fields(inputs, outputs, index)
        with self.assertRaises(ValueError):
            otda_all_fields(1, 1, 0, script_code=b"")

    @unittest.skipUnless(find_spec("tx_engine"), "requires the independent chain-gang evaluator")
    def test_complete_input_binds_parsed_fields_to_actual_chronicle_preimage(self):
        from shared.chain_gang import validate_at_heights

        profile = make_transaction(2, 2)
        output_bytes = b"".join(item.serialize() for item in profile.outputs)
        lock = (
            asm("OP_DUP OP_HASH256 OP_TOALTSTACK") + otda_all_fields(2, 2, 1)
            + asm("OP_DROP OP_SHA256") + push(sha256(output_bytes).digest()) + asm("OP_EQUALVERIFY")
            + asm("OP_2DROP OP_2DROP OP_DROP OP_FROMALTSTACK") + binding_der()
            + push(b"\x61") + asm("OP_CAT") + COMPACT_SUFFIX
        )
        parents = (
            Transaction((Input(b"a" * 32, 0),), (Output(10_000, asm("OP_1")),)),
            Transaction((Input(b"b" * 32, 0),), (Output(10_000, lock),)),
        )
        candidate = replace(profile, inputs=tuple(
            replace(txin, txid=parent.txid_wire(), vout=0, script=b"")
            for txin, parent in zip(profile.inputs, parents, strict=True)
        ))
        preimage = preimage_otda(candidate, 1, COMPACT_SCRIPTCODE, 0x61)
        signed = candidate.with_script(1, push(preimage))
        validate_at_heights(signed, parents, spend_height=4, activation_height=3, utxo_heights=(2, 3))

        stale = replace(signed, outputs=(signed.outputs[0], replace(signed.outputs[1], value=2)))
        with self.assertRaises(ValueError):
            validate_at_heights(stale, parents, spend_height=4, activation_height=3, utxo_heights=(2, 3))
        with self.assertRaises(ValueError):
            validate_at_heights(signed, parents, spend_height=2, activation_height=3, utxo_heights=(1, 1))

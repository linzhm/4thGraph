import unittest
from types import SimpleNamespace
from unittest.mock import patch

from parent_binding import ParentBinding
from parent_binding_script import parent_binding_limbs_script, parent_binding_proof_gate, select_bound_output_script
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, encode_num, number, push
from shared.transaction import Output, hash256
from statement import public_inputs


class ParentBindingScriptTests(unittest.TestCase):
    def setUp(self):
        self.outputs = (Output(1024, asm("OP_1")), Output(900, asm("OP_1") * 253), Output(0, b""))
        self.vector = b"".join(output.serialize() for output in self.outputs)
        self.asset, self.guard, self.txid, self.parent = (bytes([i]) * 32 for i in (1, 2, 3, 4))

    def test_wire_statement_matches_host_in_both_sighash_modes(self):
        limbs = parent_binding_limbs_script(self.asset)
        seen = []
        for kind in (0x41, 0x61):
            binding = ParentBinding(self.asset, self.guard, kind, self.txid, hash256(self.vector), 3, self.parent)
            fields = (self.guard, bytes([kind]), self.txid, self.vector, bytes([3, 0, 0, 0]), self.parent)
            expected = list(map(encode_num, public_inputs(binding.statement())))
            self.assertEqual(evaluate(b"".join(map(push, fields)) + limbs), (expected, []))
            seen.append(expected)
        self.assertNotEqual(*seen)
        for kind in (b"\x43", b"\x41\0", b"\x01"):
            fields = (self.guard, kind, self.txid, self.vector, bytes([3, 0, 0, 0]), self.parent)
            with self.assertRaises(ScriptError):
                evaluate(b"".join(map(push, fields)) + limbs)

    def test_selected_output_uses_exact_canonical_field_boundaries(self):
        parser = select_bound_output_script(4)
        for index, out in enumerate(self.outputs):
            arguments = push(self.vector) + push(bytes([3, 0, 0, 0])) + number(index)
            self.assertEqual(evaluate(arguments + parser), ([out.value.to_bytes(8, "little"), out.script], []))

        first = self.outputs[0].serialize()
        redundant_varint = first[:8] + b"\xfd\x01\0" + first[9:] + self.vector[len(first):]
        for fields, count, index in (
            (self.vector, 2, 0), (self.vector, 4, 0), (self.vector, 3, 3), (self.vector, 3, -1),
            (self.vector + b"\x00", 3, 0), (redundant_varint, 3, 0),
        ):
            with self.assertRaises(ScriptError):
                evaluate(push(fields) + push(count.to_bytes(4, "little")) + number(index) + parser)

    def test_gate_passes_bound_limbs_and_returns_the_actual_outpoint_slot(self):
        count = (3).to_bytes(4, "little")
        binding = ParentBinding(self.asset, self.guard, 0x61, self.txid, hash256(self.vector), 3, self.parent)
        high, low = map(encode_num, public_inputs(binding.statement()))
        check_limbs = push(low) + asm("OP_EQUALVERIFY") + push(high) + asm("OP_EQUALVERIFY OP_1")
        # Isolate the stack contract from the independent Groth16 circuit.
        with patch("parent_binding_script.locking_script", return_value=(check_limbs, None, None)):
            gate = parent_binding_proof_gate(SimpleNamespace(ic=range(3)), self.asset, max_outputs=4)

        for vout, output in enumerate(self.outputs):
            fields = (self.guard, b"\x61", self.txid + vout.to_bytes(4, "little"), self.vector, count, self.parent)
            expected = [output.value.to_bytes(8, "little"), output.script, self.parent]
            self.assertEqual(evaluate(b"".join(map(push, fields)) + gate), (expected, []))

        for guard, kind, txid, index in (
            (b"\x55" * 32, 0x61, self.txid, 0), (self.guard, 0x41, self.txid, 0),
            (self.guard, 0x61, self.parent, 0), (self.guard, 0x61, self.txid, 3),
        ):
            fields = (guard, bytes([kind]), txid + index.to_bytes(4, "little"), self.vector, count, self.parent)
            with self.assertRaises(ScriptError):
                evaluate(b"".join(map(push, fields)) + gate)

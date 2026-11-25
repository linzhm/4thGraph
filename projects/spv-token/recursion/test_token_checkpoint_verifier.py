from dataclasses import replace
from importlib.util import find_spec
import unittest

import token_checkpoint_verifier as checkpoint
from operational_token import TokenPolicy, freeze_witness, ordinary_witness
from parent_prefix import parent_prefix
from shared.evaluate import evaluate
from shared.script import asm, encode_num
from shared.transaction import Input, Output, Transaction, hash256
from statement import public_inputs
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from transfer import compact_verifier_binding


class TokenCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.owner, self.sign_owner = fixture_signer(11)
        self.issuer, self.sign_issuer = fixture_signer(12)
        self.context = {"spend_height": 100, "activation_height": 2, "utxo_heights": (3, 3)}

    @staticmethod
    def funding(tag, outputs):
        return Transaction((Input(hash256(tag), 0),), outputs)

    def parents(self, lock, tag=b"main"):
        policy = TokenPolicy((lock,), self.issuer)
        state = TokenState(b"a" * 32, 640, self.owner)
        active = Output(1000, policy.lock(state))
        frozen = Output(1000, policy.lock(replace(state, frozen=True)))
        origin = self.funding(tag + b" mint", (active,))
        fees = self.funding(tag + b" fees", (Output(10_000, asm("OP_1")),) * 2)
        freeze = Transaction((Input(origin.txid_wire(), 0), Input(fees.txid_wire(), 0)), (frozen,))
        freeze = freeze.with_script(0, freeze_witness(freeze, 0, origin, policy, self.sign_issuer))
        for sequence in range(64):
            draft = Transaction((Input(freeze.txid_wire(), 0, sequence=sequence), Input(fees.txid_wire(), 1)), (active,))
            material = freeze_witness(draft, 0, freeze, policy, self.sign_issuer)
            if len(material) == checkpoint.NATIVE_WITNESS_BYTES:
                resume = draft.with_script(0, material)
                return policy, origin, fees, freeze, resume
        raise AssertionError("fixture did not produce the configured native witness width")

    @unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
    def test_raw_gate_accepts_a_real_unfreeze_and_rejects_wrong_outpoint_or_output(self):
        from shared.chain_gang import validate_at_heights

        gate = checkpoint.raw_verifier_lock()
        policy, origin, fees, freeze, parent = self.parents(gate)
        verifier = self.funding(b"verifier", (Output(100_000, gate),))
        validate_at_heights(freeze, (origin, fees), **self.context)
        validate_at_heights(parent, (freeze, fees), **self.context)
        tx = Transaction((Input(verifier.txid_wire(), 0), Input(parent.txid_wire(), 0)), parent.outputs)
        raw = parent.serialize()

        def witness(candidate, material, actual_parent, signer=self.sign_owner):
            return candidate.with_script(0, material).with_script(
                1, ordinary_witness(candidate, 1, actual_parent, policy, verifier, signer),
            )

        signed = witness(tx, checkpoint.raw_verifier_material(tx, verifier, raw), parent)
        validate_at_heights(signed, (verifier, parent), **self.context)
        _, other_origin, other_fees, other_freeze, other = self.parents(gate, b"other")
        validate_at_heights(other_freeze, (other_origin, other_fees), **self.context)
        validate_at_heights(other, (other_freeze, other_fees), **self.context)
        changed_outpoint = replace(tx, inputs=(tx.inputs[0], Input(other.txid_wire(), 0)))
        changed_output = replace(tx, outputs=(replace(tx.outputs[0], value=999),))
        extra_output = replace(tx, outputs=(tx.outputs[0], Output(1, asm("OP_1"))))
        for bad, actual in ((changed_outpoint, other), (changed_output, parent), (extra_output, parent)):
            signed_bad = witness(bad, checkpoint.raw_verifier_material(bad, verifier, raw), actual)
            with self.subTest(txid=bad.txid()), self.assertRaisesRegex((ValueError, RuntimeError), "Error evaluating the script"):
                validate_at_heights(signed_bad, (verifier, actual), **self.context)

    @unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
    def test_checkpoint_uses_the_same_actual_rollover_and_binds_all_public_fields(self):
        from shared.chain_gang import validate_at_heights

        relation = checkpoint.statement_script()
        # This stand-in drops the public limbs. It isolates the native context checks.
        gate = relation + asm("OP_2DROP OP_1") + compact_verifier_binding()
        policy, _, fees, freeze, parent = self.parents(gate)
        validate_at_heights(parent, (freeze, fees), **self.context)
        verifier = self.funding(b"checkpoint verifier", (Output(10_000, gate),))
        prefix = parent_prefix(parent.serialize())
        tx = Transaction((Input(verifier.txid_wire(), 0), Input(parent.txid_wire(), 0)), parent.outputs)
        state, suffix = prefix.state, prefix.suffix
        expected = (checkpoint.DOMAIN + parent.txid_wire() + state + checkpoint.PROFILE + hash256(suffix) + bytes(32))
        self.assertEqual(checkpoint.statement_bytes(parent.txid_wire(), state, suffix), expected)
        self.assertEqual((prefix.processed_bytes, prefix.output_count_offset), (1856, 1871))
        self.assertEqual(suffix[16:1573], parent.outputs[0].serialize())
        for disclosed_state, disclosed_suffix, message in (
            (state, suffix, expected),
            (bytes(32), suffix, checkpoint.statement_bytes(parent.txid_wire(), bytes(32), suffix)),
            (state, suffix[:-1] + b"\x01", checkpoint.statement_bytes(parent.txid_wire(), state, suffix[:-1] + b"\x01")),
        ):
            material = checkpoint.verifier_material(tx, verifier, disclosed_state, disclosed_suffix)
            self.assertEqual(evaluate(material + relation)[0], list(map(encode_num, public_inputs(message))))
        self.assertNotEqual(public_inputs(expected), public_inputs(checkpoint.statement_bytes(bytes(32), state, suffix)))

        for candidate in (tx, replace(tx, outputs=(replace(tx.outputs[0], value=999),))):
            material = checkpoint.verifier_material(candidate, verifier, state, suffix)
            native = ordinary_witness(candidate, 1, parent, policy, verifier, self.sign_owner)
            signed = candidate.with_script(0, material).with_script(1, native)
            if candidate == tx:
                validate_at_heights(signed, (verifier, parent), **self.context)
            else:
                with self.assertRaisesRegex((ValueError, RuntimeError), "Error evaluating the script"):
                    validate_at_heights(signed, (verifier, parent), **self.context)


if __name__ == "__main__":
    unittest.main()

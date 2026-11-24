from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import unittest

from chronicle_preimage import CHRONICLE_ALL, LEGACY_ALL
from committed_verifier import load_verifying_key
from continuity_preimage import prior_digest, prior_preimage
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier
from mint import MintPolicy
from parent_binding import derive_parent_binding, verify_parent_binding
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_forkid, preimage_otda
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from transfer import COMPACT_SCRIPTCODE

RECEIPT = ParentReceipt((b"p" * 32,))
FIXTURE_WITNESS = push(b"reference witness without a proof" * 9)
PREFIX = b"caller stack"
ALT = b"caller altstack"
SEQUENCE_TAG = {LEGACY_ALL: 0x80000041, CHRONICLE_ALL: 0x80000061}


class ChronicleParentContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key, commitment = load_verifying_key(json.loads(
            (Path(__file__).parent / "testdata/bsb22-proof.json").read_text()
        ))
        issuer, _ = fixture_signer(13)
        freeze, _ = fixture_signer(12)
        cls.owner, _ = fixture_signer(11)
        anchor = Input(b"a" * 32, 0)
        asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)
        template = MintPolicy(asset, 84532, b"r" * 20, issuer, lambda _: b"")
        cls.verifier = ContinuityVerifier(template, freeze, key, commitment, b"k" * 32,
                                          certified_mints=True, certified_admin=True, chronicle_all=True)
        cls.funding = Transaction(
            (Input(b"f" * 32, 1, push(b"funding witness"), sequence=78),),
            (Output(98_764, cls.verifier.lock),), version=2, locktime=9,
        )
        cls.funding_raw = cls.funding.serialize()
        cls.guard = sha256(blob(cls.funding.outputs[0].script)).digest()
        cls.prev_script = prior_preimage(certified_admin=True, chronicle_all=True)
        cls.digest_script = prior_digest(asset.asset_id(), cls.verifier.key_digest,
                                         certified_admin=True, chronicle_all=True)

    def parent(self, verifier_index, sighash_type, *, prefix=b"", version=2):
        verifier_input = Input(
            self.funding.txid_wire(), 0, prefix + FIXTURE_WITNESS, sequence=SEQUENCE_TAG[sighash_type],
        )
        other = Input(b"t" * 32, 0, push(b"\x43") + FIXTURE_WITNESS, sequence=125)
        first_token = self.verifier.mint_policy.token_output(21, self.owner)
        if verifier_index == 0:
            return Transaction(
                (verifier_input, other),
                (first_token, self.verifier.mint_policy.token_output(13, self.owner), RECEIPT.output()),
                version=version, locktime=45,
            )
        return Transaction((other, verifier_input), (first_token, RECEIPT.output()), version=version, locktime=46)

    def run_script(self, tx, funding_raw=None, *, fragment=None):
        material = [PREFIX, tx.serialize(), self.funding_raw if funding_raw is None else funding_raw, self.guard]
        save_alt = push(ALT) + asm("OP_TOALTSTACK")
        return evaluate(save_alt + (self.prev_script if fragment is None else fragment), material)

    def assert_parent_context(self, tx, index, sighash_type, *, funding=None):
        funded = self.funding if funding is None else funding
        raw_funding = self.funding_raw if funding is None else funded.serialize()
        if sighash_type == LEGACY_ALL:
            expected = preimage_forkid(tx, index, funded.outputs[0].value, COMPACT_SCRIPTCODE, LEGACY_ALL)
        else:
            expected = preimage_otda(tx, index, COMPACT_SCRIPTCODE, CHRONICLE_ALL)
        expected_digest = RECEIPT.digest(self.verifier.asset.asset_id(), self.verifier.key_digest, hash256(expected))
        self.assertEqual(self.run_script(tx, raw_funding), ([PREFIX, RECEIPT.payload(), expected], [ALT]))
        self.assertEqual(self.run_script(tx, raw_funding, fragment=self.digest_script), ([PREFIX, expected_digest], [ALT]))
        binding = derive_parent_binding(self.verifier, tx.serialize(), raw_funding)
        self.assertEqual(binding.sighash_type, sighash_type)
        self.assertEqual(binding.parent_txid_wire, tx.txid_wire())
        self.assertEqual(binding.verifier_script_field_hash, self.guard)
        self.assertEqual(binding.hash_outputs, hash256(b"".join(output.serialize() for output in tx.outputs)))
        self.assertEqual(binding.output_count, len(tx.outputs))
        self.assertEqual(binding.continuity_digest, expected_digest)
        return binding

    def test_each_actual_verifier_position_and_signature_type(self):
        for index in (0, 1):
            for sighash_type in (LEGACY_ALL, CHRONICLE_ALL):
                for version in (1, 2):
                    with self.subTest(index=index, sighash_type=hex(sighash_type), version=version):
                        self.assert_parent_context(self.parent(index, sighash_type, version=version), index, sighash_type)

    def test_first_witness_item_never_selects_context_but_changes_exact_txid(self):
        for index in (0, 1):
            for sighash_type in (LEGACY_ALL, CHRONICLE_ALL):
                opposite = bytes([LEGACY_ALL if sighash_type == CHRONICLE_ALL else CHRONICLE_ALL])
                base = self.assert_parent_context(self.parent(index, sighash_type), index, sighash_type)
                prefixes = (
                    push(opposite), b"\x4c\x01" + opposite, b"\x4d\x01\x00" + opposite,
                    b"\x4e\x01\x00\x00\x00" + opposite, b"\x51", push(b"arbitrary"),
                )
                for prefix in prefixes:
                    with self.subTest(index=index, sighash_type=hex(sighash_type), push_prefix=prefix.hex()):
                        tx = self.parent(index, sighash_type, prefix=prefix)
                        changed = self.assert_parent_context(tx, index, sighash_type)
                        self.assertEqual(replace(changed, parent_txid_wire=base.parent_txid_wire), base)
                        self.assertNotEqual(changed.parent_txid_wire, base.parent_txid_wire)
                        with self.assertRaisesRegex(ValueError, "do not match"):
                            verify_parent_binding(self.verifier, base, tx.serialize(), self.funding_raw)

    def test_nonverifier_input_sequence_and_outpoint_are_authenticated_without_dispatch(self):
        for index in (0, 1):
            for sighash_type in (LEGACY_ALL, CHRONICLE_ALL):
                tx = self.parent(index, sighash_type)
                base = self.assert_parent_context(tx, index, sighash_type)
                other = 1 - index
                opposite = LEGACY_ALL if sighash_type == CHRONICLE_ALL else CHRONICLE_ALL
                candidates = (
                    replace(tx.inputs[other], sequence=SEQUENCE_TAG[opposite]),
                    replace(tx.inputs[other], txid=b"y" * 32),
                )
                for changed in candidates:
                    with self.subTest(index=index, sighash_type=hex(sighash_type), changed=changed):
                        inputs = list(tx.inputs)
                        inputs[other] = changed
                        bound = self.assert_parent_context(replace(tx, inputs=tuple(inputs)), index, sighash_type)
                        self.assertNotEqual(bound.continuity_digest, base.continuity_digest)
                changed_witness = tx.with_script(other, push(bytes([opposite])))
                bound = self.assert_parent_context(changed_witness, index, sighash_type)
                self.assertEqual(bound.continuity_digest, base.continuity_digest)
                self.assertNotEqual(bound.parent_txid_wire, base.parent_txid_wire)

    def test_wrong_actual_funding_fails_in_both_branches(self):
        other_funding = replace(self.funding, locktime=10)
        wrong_lock = replace(self.funding, outputs=(replace(self.funding.outputs[0], script=b"\x51"),))
        for index in (0, 1):
            for sighash_type in (LEGACY_ALL, CHRONICLE_ALL):
                tx = self.parent(index, sighash_type)
                wrong_vout = list(tx.inputs)
                wrong_vout[index] = replace(wrong_vout[index], vout=1)
                wrong_lock_vin = list(tx.inputs)
                wrong_lock_vin[index] = replace(wrong_lock_vin[index], txid=wrong_lock.txid_wire())
                variants = (
                    ("txid", tx, other_funding.serialize()),
                    ("vout", replace(tx, inputs=tuple(wrong_vout)), self.funding_raw),
                    ("lock", replace(tx, inputs=tuple(wrong_lock_vin)), wrong_lock.serialize()),
                )
                for kind, parent, raw in variants:
                    with self.subTest(index=index, sighash_type=hex(sighash_type), funding=kind):
                        with self.assertRaises(ScriptError):
                            self.run_script(parent, raw)
                        with self.assertRaisesRegex(ValueError, "invalid verifier parent"):
                            derive_parent_binding(self.verifier, parent.serialize(), raw)

    def test_funded_amount_is_taken_from_the_actual_verifier_output(self):
        alternate = replace(self.funding, outputs=(replace(self.funding.outputs[0], value=98_765),))
        for index in (0, 1):
            for sighash_type in (LEGACY_ALL, CHRONICLE_ALL):
                with self.subTest(index=index, sighash_type=hex(sighash_type)):
                    tx = self.parent(index, sighash_type)
                    base = self.assert_parent_context(tx, index, sighash_type)
                    inputs = list(tx.inputs)
                    inputs[index] = replace(inputs[index], txid=alternate.txid_wire())
                    changed = self.assert_parent_context(replace(tx, inputs=tuple(inputs)), index, sighash_type,
                                                         funding=alternate)
                    self.assertEqual(changed.hash_outputs, base.hash_outputs)
                    self.assertNotEqual(changed.continuity_digest, base.continuity_digest)

    def test_invalid_verifier_sequence_cannot_dispatch_through_a_witness_marker(self):
        for index in (0, 1):
            for invalid_sequence in (0x41, 0x61, 0x80000043, 0x80000063, 0x80000161, 0xffffffff):
                with self.subTest(index=index, sequence=hex(invalid_sequence)):
                    tx = self.parent(index, CHRONICLE_ALL, prefix=push(b"\x61"))
                    inputs = list(tx.inputs)
                    inputs[index] = replace(inputs[index], sequence=invalid_sequence)
                    tx = replace(tx, inputs=tuple(inputs))
                    with self.assertRaises(ScriptError):
                        self.run_script(tx)
                    with self.assertRaises(ValueError):
                        derive_parent_binding(self.verifier, tx.serialize(), self.funding_raw)
            unsigned = self.parent(index, CHRONICLE_ALL).with_script(index, b"")
            with self.assertRaisesRegex(ValueError, "missing witness"):
                derive_parent_binding(self.verifier, unsigned.serialize(), self.funding_raw)

    def test_other_supported_sequence_tag_cannot_reuse_reference_statement(self):
        for index in (0, 1):
            chronicle_tx = self.parent(index, CHRONICLE_ALL)
            chronicle = self.assert_parent_context(chronicle_tx, index, CHRONICLE_ALL)
            legacy_tx = self.parent(index, LEGACY_ALL)
            legacy = self.assert_parent_context(legacy_tx, index, LEGACY_ALL)
            self.assertEqual(chronicle_tx.inputs[index].script, legacy_tx.inputs[index].script)
            self.assertEqual(chronicle.hash_outputs, legacy.hash_outputs)
            self.assertNotEqual(chronicle.continuity_digest, legacy.continuity_digest)
            with self.assertRaisesRegex(ValueError, "do not match"):
                verify_parent_binding(self.verifier, chronicle, legacy_tx.serialize(), self.funding_raw)


if __name__ == "__main__":
    unittest.main()

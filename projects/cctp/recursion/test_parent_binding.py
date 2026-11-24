from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import unittest

from capacity_verifier import CapacityVerifier
from committed_verifier import load_verifying_key
from continuity_statement import ParentReceipt
from continuity_verifier import ContinuityVerifier
from mint import MintPolicy
from operational_token import TokenPolicy
from parent_binding import PARENT_BINDING_DOMAIN, ParentBinding, derive_parent_binding, verify_parent_binding
from shared.script import push
from shared.transaction import Input, Output, Transaction, blob, compact, hash256, preimage_all
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from transfer import COMPACT_SCRIPTCODE

FIXTURE_WITNESS = push(b"reference fixture witness; never submitted")
RECEIPT = ParentReceipt((b"p" * 32,))


def funding(lock, tag=1):
    return Transaction((Input(bytes([tag]) * 32, 0),), (Output(100_000, lock),))


def output_vector(tx):
    return b"".join(output.serialize() for output in tx.outputs)


class ParentBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key, commitment = load_verifying_key(json.loads(
            (Path(__file__).parent / "testdata/bsb22-proof.json").read_text()
        ))
        issuer, _ = fixture_signer(13)
        freeze, _ = fixture_signer(12)
        cls.owner, _ = fixture_signer(11)
        asset = AssetDescriptor(1, Input(b"a" * 32, 0).outpoint(), 6, 7, b"r" * 32, b"p" * 32)
        mint = MintPolicy(asset, 84532, b"r" * 20, issuer, lambda _: b"")
        cls.profile = dict(certified_mints=True, certified_admin=True, shared_ordinary_guard=True)
        cls.common = mint, freeze, key, commitment, b"k" * 32
        cls.verifier = ContinuityVerifier(*cls.common, **cls.profile)
        cls.funding = funding(cls.verifier.lock)
        cls.funding_raw = cls.funding.serialize()
        cls.token = cls.verifier.mint_policy.token_output(27, cls.owner)
        cls.parent = Transaction(
            (Input(cls.funding.txid_wire(), 0, FIXTURE_WITNESS, sequence=8), Input(b"t" * 32, 2)),
            (cls.token, cls.verifier.mint_policy.token_output(31, cls.owner), RECEIPT.output()),
            version=3, locktime=5,
        )

    def binding(self, parent=None, funder=None):
        raw = (parent or self.parent).serialize()
        return derive_parent_binding(self.verifier, raw, self.funding_raw if funder is None else funder.serialize())

    def test_canonical_wire_fields_match_the_actual_context(self):
        binding = self.binding()
        vector = output_vector(self.parent)
        preimage = preimage_all(self.parent, 0, self.funding.outputs[0].value, COMPACT_SCRIPTCODE)
        expected = (
            b"BSV/CCTP/parent-binding/v1\x00" + self.verifier.asset.asset_id()
            + sha256(blob(self.funding.outputs[0].script)).digest() + b"\x41"
            + bytes.fromhex(self.parent.txid())[::-1] + preimage[-40:-8] + b"\x03\x00\x00\x00"
            + RECEIPT.digest(self.verifier.asset.asset_id(), self.verifier.key_digest, hash256(preimage))
        )
        self.assertEqual(binding.statement(), expected)
        self.assertEqual(ParentBinding.parse(expected), binding)
        self.assertEqual(binding.sighash_type, 0x41)
        self.assertEqual(binding.digest(), hash256(expected))
        self.assertEqual(binding.hash_outputs, hash256(vector))
        self.assertEqual(binding.verify_outputs(vector), self.parent.outputs)
        self.assertEqual(verify_parent_binding(self.verifier, binding, self.parent.serialize(), self.funding_raw), binding)
        for invalid in (expected[1:], expected + b"\x00", b"x" + expected[1:]):
            with self.assertRaises(ValueError):
                ParentBinding.parse(invalid)

    def test_both_sighash_types_encode_but_fixed_v3_only_derives_legacy(self):
        legacy = self.binding()
        chronicle = replace(legacy, sighash_type=0x61)
        field = len(PARENT_BINDING_DOMAIN) + 64
        self.assertEqual(chronicle.statement(), legacy.statement()[:field] + b"\x61" + legacy.statement()[field + 1:])
        self.assertEqual(ParentBinding.parse(chronicle.statement()), chronicle)
        self.assertNotEqual(legacy.digest(), chronicle.digest())
        with self.assertRaisesRegex(ValueError, "do not match"):
            verify_parent_binding(self.verifier, chronicle, self.parent.serialize(), self.funding_raw)
        with self.assertRaisesRegex(ValueError, "SIGHASH_ALL"):
            replace(legacy, sighash_type=0x43)

        class WrongContext(ContinuityVerifier):
            def context(self, tx, funding):
                receipt, _ = super().context(tx, funding)
                return receipt, b"x" * 32

        other = WrongContext(*self.common, **self.profile)
        with self.assertRaisesRegex(ValueError, "fixed 0x41"):
            derive_parent_binding(other, self.parent.serialize(), self.funding_raw)

    def test_signed_txid_cannot_be_substituted_for_the_same_continuity_digest(self):
        original = self.binding()
        changed = self.parent.with_script(0, push(b"a different test witness"))
        bound_changed = self.binding(changed)
        self.assertEqual(bound_changed.continuity_digest, original.continuity_digest)
        self.assertEqual(bound_changed.hash_outputs, original.hash_outputs)
        self.assertNotEqual(bound_changed.parent_txid_wire, original.parent_txid_wire)
        with self.assertRaisesRegex(ValueError, "do not match"):
            verify_parent_binding(self.verifier, original, changed.serialize(), self.funding_raw)
        with self.assertRaisesRegex(ValueError, "missing witness"):
            self.binding(self.parent.with_script(0, b""))

    def test_actual_vin_one_and_funded_amount(self):
        parent = Transaction(
            (Input(b"t" * 32, 0), Input(self.funding.txid_wire(), 0, FIXTURE_WITNESS)),
            (self.token, RECEIPT.output()),
        )
        alternate = replace(self.funding, outputs=(replace(self.funding.outputs[0], value=100_001),))
        old = self.binding(parent)
        with self.assertRaisesRegex(ValueError, "invalid verifier parent"):
            self.binding(parent, alternate)
        parent = replace(parent, inputs=(parent.inputs[0], replace(parent.inputs[1], txid=alternate.txid_wire())))
        new = self.binding(parent, alternate)
        self.assertEqual(old.hash_outputs, new.hash_outputs)
        self.assertEqual(old.verifier_script_field_hash, new.verifier_script_field_hash)
        self.assertNotEqual(old.continuity_digest, new.continuity_digest)
        actual_context = hash256(preimage_all(parent, 1, alternate.outputs[0].value, COMPACT_SCRIPTCODE))
        self.assertEqual(new.continuity_digest,
                         RECEIPT.digest(self.verifier.asset.asset_id(), self.verifier.key_digest, actual_context))

    def test_rejects_wrong_funding_vout_lock_and_noncanonical_wire(self):
        unknown_lock = funding(b"\x51")
        wrong_lock = replace(self.parent, inputs=(replace(self.parent.inputs[0], txid=unknown_lock.txid_wire()),
                                                 self.parent.inputs[1]))
        wrong_vout = replace(self.parent, inputs=(replace(self.parent.inputs[0], vout=1), self.parent.inputs[1]))
        for parent, funder in ((wrong_lock, unknown_lock), (wrong_vout, self.funding)):
            with self.assertRaisesRegex(ValueError, "invalid verifier parent"):
                self.binding(parent, funder)

        parent_raw = self.parent.serialize()
        nonminimal = parent_raw[:4] + b"\xfd\x02\x00" + parent_raw[5:]
        for raw, fund in ((nonminimal, self.funding_raw), (parent_raw + b"x", self.funding_raw),
                          (parent_raw, self.funding_raw[:-1])):
            with self.assertRaises(ValueError):
                derive_parent_binding(self.verifier, raw, fund)

    def test_output_vector_consumes_exactly_the_count_and_canonical_lengths(self):
        binding = self.binding()
        outputs = tuple(Output(i, bytes([i % 256])) for i in range(257))
        vector = b"".join(output.serialize() for output in outputs)
        wide = replace(binding, output_count=257, hash_outputs=hash256(vector))
        self.assertEqual(wide.verify_outputs(vector), outputs)
        self.assertEqual(ParentBinding.parse(wide.statement()).output_count, 257)
        for count in (256, 258):
            with self.assertRaises(ValueError):
                replace(wide, output_count=count).verify_outputs(vector)

        first = outputs[0].serialize()
        malformed_length = first[:8] + b"\xfd\x01\x00" + first[9:]
        for malformed, count in ((vector + b"x", 257), (vector[:-1], 257),
                                 (compact(257) + vector, 257), (malformed_length, 1)):
            with self.assertRaises(ValueError):
                replace(wide, output_count=count, hash_outputs=hash256(malformed)).verify_outputs(malformed)
        with self.assertRaisesRegex(ValueError, "does not match"):
            wide.verify_outputs(vector[:-1] + b"x")

    def test_designated_outpoint_requires_exact_active_asset_and_guard(self):
        policy = self.verifier.policy
        asset_id = self.verifier.asset.asset_id()
        binding = self.binding()
        vector = output_vector(self.parent)
        outpoint = Input(binding.parent_txid_wire, 0)
        self.assertEqual(binding.verify_token_at(vector, outpoint, policy), TokenState(asset_id, 27, self.owner))
        invalid = (replace(outpoint, txid=outpoint.txid[::-1]), replace(outpoint, vout=3), replace(outpoint, vout=2))
        for item in invalid:
            with self.assertRaises(ValueError):
                binding.verify_token_at(vector, item, policy)
        wrong_policy = TokenPolicy((b"wrong",), self.verifier.freeze_key,
                                   certified_admin=True, shared_ordinary_guard=True)
        with self.assertRaisesRegex(ValueError, "does not match"):
            binding.verify_token_at(vector, outpoint, wrong_policy)

        variants = (
            (TokenState(b"z" * 32, 27, self.owner), policy),
            (TokenState(asset_id, 27, self.owner), wrong_policy),
            (TokenState(asset_id, 27, self.owner, frozen=True), policy),
        )
        for token, token_policy in variants:
            changed = replace(self.parent, outputs=(Output(27, token_policy.lock(token)), *self.parent.outputs[1:]))
            actual = self.binding(changed)
            origin = Input(actual.parent_txid_wire, 0)
            with self.assertRaises(ValueError):
                actual.verify_token_at(output_vector(changed), origin, policy)
            if token.frozen:
                self.assertEqual(actual.verify_token_at(output_vector(changed), origin, policy, allow_frozen=True), token)

    def test_capacity_path_uses_existing_context_verification(self):
        verifier = CapacityVerifier(*self.common, **self.profile, capacity=64)
        actual_funding = funding(verifier.lock, tag=2)
        companion = funding(verifier.policy.shared_guard_lock(), tag=3)
        token_outputs = (verifier.mint_policy.token_output(2, self.owner),) * 64
        capacity_tx = verifier.prepare_capacity(
            17, (Input(b"x" * 32, 1),), token_outputs, actual_funding, companion, RECEIPT,
        ).with_script(0, FIXTURE_WITNESS)
        raw_funding = actual_funding.serialize()
        binding = derive_parent_binding(verifier, capacity_tx.serialize(), raw_funding)
        self.assertEqual(binding.output_count, 65)
        self.assertEqual(binding.continuity_digest, verifier.proof_digest(capacity_tx, actual_funding))
        self.assertEqual(binding.verify_outputs(output_vector(capacity_tx))[:64], token_outputs)
        stale = replace(capacity_tx, locktime=capacity_tx.locktime + 1)
        with self.assertRaisesRegex(ValueError, "does not encode the actual compact verifier context"):
            derive_parent_binding(verifier, stale.serialize(), raw_funding)


if __name__ == "__main__":
    unittest.main()

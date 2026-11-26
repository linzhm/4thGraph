"""Conformance for the prebuilt full-mode template and OTDA reconstruction."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tx_engine import Script, Tx, TxIn, TxOut

from fixed_templates import LEGACY_TEMPLATE_VERSION, RELEASE_DIRECTORY, TEMPLATE_DIRECTORY, TEMPLATE_VERSION
from fixed_templates import compiled_template, otda_reconstruction
from generate_templates import build_artifacts, scheduled_artifacts
from p2pkh_r1 import locking_script_from_owner_hash, locking_script_from_public_key, recognize
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.transaction import Transaction, hash256, preimage_forkid, preimage_otda
from test_payment import check, child, fixture_signature, parent, signer
from signature import UNIVERSAL_FLAGS, authorization, current_input_unlock
from specialize import specialized_lock
from wallet import sign_spend


def script(raw):
    value = Script()
    value.append_data(raw)
    return value


P2PKH = script(bytes.fromhex("76a914" + "00" * 20 + "88ac"))
CHRONICLE_MAINNET_HEIGHT = 943_835


class FixedTemplateTests(unittest.TestCase):
    def test_default_wallet_and_cli_create_the_versioned_template(self):
        _, key, owner = signer(17)
        layout = json.loads((RELEASE_DIRECTORY / "layout.json").read_text(encoding="ascii"))
        self.assertEqual(layout["template_version"], TEMPLATE_VERSION)
        self.assertEqual({int(mode, 16) for mode in layout["supported_sighash_types"]}, UNIVERSAL_FLAGS)
        script = locking_script_from_owner_hash(owner)
        self.assertEqual(len(script), 46302)
        self.assertEqual(script, locking_script_from_public_key(key, template_version=TEMPLATE_VERSION))
        self.assertEqual(recognize(script), owner)
        previous = locking_script_from_owner_hash(owner, template_version=LEGACY_TEMPLATE_VERSION)
        self.assertEqual(len(previous), 59582)
        self.assertEqual(recognize(previous), owner)
        cli = [sys.executable, str(Path(__file__).with_name("generate_lock.py")), "--owner-hash160", owner.hex()]
        for options, version, expected in (([], TEMPLATE_VERSION, script),
                                           (["--version", LEGACY_TEMPLATE_VERSION], LEGACY_TEMPLATE_VERSION, previous)):
            with self.subTest(version=version):
                manifest = json.loads(subprocess.check_output([*cli, *options]))
                self.assertEqual(manifest["template_version"], version)
                self.assertEqual(manifest["script_sha256"], sha256(expected).hexdigest())
                self.assertEqual(subprocess.check_output([*cli, *options, "--format", "raw"]), expected)

    def test_artifacts_and_owner_vectors(self):
        for directory, artifacts in ((TEMPLATE_DIRECTORY, build_artifacts()), (RELEASE_DIRECTORY, scheduled_artifacts())):
            for file, content in artifacts.items():
                self.assertEqual((directory / file).read_text(encoding="ascii"), content, file)
        layout = json.loads((TEMPLATE_DIRECTORY / "layout.json").read_text(encoding="ascii"))
        template = compiled_template()
        for vector in layout["owner_vectors"]:
            with self.subTest(owner=vector["owner_hash160"]):
                owner = bytes.fromhex(vector["owner_hash160"])
                raw = locking_script_from_owner_hash(owner, compiled_curve=True)
                self.assertEqual(sha256(raw).hexdigest(), vector["script_sha256"])
                self.assertEqual(recognize(raw), owner)
                for i in (0, template.owner_start - 1, template.owner_end, len(raw) - 1):
                    changed = raw[:i] + bytes([raw[i] ^ 1]) + raw[i + 1:]
                    self.assertIsNone(recognize(changed))
                self.assertIsNone(recognize(raw[:-1]))
                self.assertIsNone(recognize(raw + bytes(1)))

    def test_complete_transactions_and_marginals(self):
        keys, locks, funding = self.funding()
        for flag, profiles in (
            (0x41, ((2, 2, 326, 95790), (3, 2, 326, 96159), (2, 3, 326, 143311))),
            (0x61, ((2, 2, 6176, 107490), (3, 2, 6217, 113832), (2, 3, 6216, 155091))),
        ):
            for m, n, unlock_bytes, tx_bytes in profiles:
                with self.subTest(flag=hex(flag), inputs=m, outputs=n):
                    prev = funding[:m]
                    outputs = [TxOut(500, lock) for lock in locks[3:3+n]]
                    unsigned = Tx(2, [TxIn(p.id(), 0, Script()) for p in prev], outputs, 0)
                    signed = self.sign(unsigned, prev, keys[:m], flag, compress=True)
                    self.check_chronicle(signed, prev)
                    self.assertEqual([len(i.script_sig.raw_serialize()) for i in signed.tx_ins], [unlock_bytes] * m)
                    self.assertEqual(len(signed.serialize()), tx_bytes)
                    if flag == 0x41:
                        for i in range(m):
                            check(signed, prev, i, chronicle=False, funding_height=1)
                    if flag == 0x61 and (m, n) == (2, 2):
                        ordinary = self.sign(unsigned, prev, keys[:m], flag, compress=False)
                        self.check_chronicle(ordinary, prev)
                        self.assertEqual(len(ordinary.serialize()), 285762)

    def test_scheduled_template_recognition_and_reconstruction(self):
        template = compiled_template(scheduled=True)
        _, program = otda_reconstruction(scheduled=True)
        self.assertEqual((len(template.script), len(program)), (46302, 3913))
        self.assertEqual(evaluate(program), (
            [template.script[:template.owner_start], template.script[template.owner_end:]], [],
        ))
        owner = bytes(range(20))
        raw = locking_script_from_owner_hash(owner, compiled_curve="scheduled")
        self.assertEqual(recognize(raw), owner)
        for offset in (0, template.owner_start - 1, template.owner_end, len(raw) - 1):
            self.assertIsNone(recognize(raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]))

    def test_scheduled_paired_otda_payment_and_marginals(self):
        keys, locks, funding = self.funding(compiled_curve="scheduled")
        shapes = ((2, 2), (3, 2), (2, 3))
        sizes = {
            0x61: (101250, 105680, 147643),
            0x63: (101179, 101634, 147492),
            0xe3: (101095, 101468, 147408),
        }
        for flag, expected_sizes in sizes.items():
            for (m, n), expected in zip(shapes, expected_sizes, strict=True):
                with self.subTest(flag=hex(flag), inputs=m, outputs=n):
                    prev = funding[:m]
                    tx = Tx(2, [TxIn(p.id(), 0, Script()) for p in prev],
                            [TxOut(500, lock) for lock in locks[3:3 + n]], 0)
                    literal = self.sign(tx, prev, keys[:m], flag, compress=False)
                    compact = self.sign(tx, prev, keys[:m], flag, compress="paired")
                    self.check_chronicle(compact, prev)
                    self.assertEqual(len(compact.serialize()), expected)
                    for index, (before, after) in enumerate(zip(literal.tx_ins, compact.tx_ins, strict=True)):
                        plain = before.script_sig.raw_serialize()
                        encoded = after.script_sig.raw_serialize()
                        self.assertEqual(evaluate(encoded), evaluate(plain))
                        if flag & 31 == 3 and index >= n:
                            self.assertEqual(encoded, plain)
                        else:
                            self.assertLess(len(encoded), len(plain))
                    if flag & 31 == 3 and m == n == 2:
                        self.check_single_amount_binding(compact, prev)

    def check_single_amount_binding(self, tx, prev):
        for changed in range(len(tx.tx_outs)):
            outputs = tx.tx_outs.copy()
            old = outputs[changed]
            outputs[changed] = TxOut(old.amount - 1, old.script_pubkey)
            modified = Tx(tx.version, tx.tx_ins, outputs, tx.locktime)
            with self.assertRaises(ValueError):
                modified.validate_at_height(prev, CHRONICLE_MAINNET_HEIGHT, "BSV_Mainnet")
            for index in range(len(prev)):
                check(modified, prev, index, valid=index != changed)

    def test_mixed_compiled_templates_and_recipient_types(self):
        keys, locks, funding = self.funding(compiled_curve="scheduled")
        legacy = script(locking_script_from_owner_hash(keys[5][2], compiled_curve=True))
        prev = funding[:2]
        tx = Tx(2, [TxIn(p.id(), 0, Script()) for p in prev],
                [TxOut(700, locks[3]), TxOut(650, legacy), TxOut(550, P2PKH)], 0)
        for flag in (0x61, 0xe1, 0x63, 0xe3):
            with self.subTest(flag=hex(flag)):
                compact = self.sign(tx, prev, keys[:2], flag, compress="paired")
                literal = self.sign(tx, prev, keys[:2], flag, compress=False)
                self.check_chronicle(compact, prev)
                for before, after in zip(literal.tx_ins, compact.tx_ins, strict=True):
                    self.assertEqual(evaluate(before.script_sig.raw_serialize()),
                                     evaluate(after.script_sig.raw_serialize()))
                    self.assertLess(len(after.script_sig.raw_serialize()), len(before.script_sig.raw_serialize()))

    def test_reconstruction_matches_signer_and_both_engines_across_modes(self):
        modes = (0x41, 0x42, 0x43, 0x61, 0x62, 0x63, 0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3)
        self.assertEqual(UNIVERSAL_FLAGS, set(modes))
        # Use three public fixture keys and three different previous locks.
        keys = [signer(i) for i in (41, 42, 43)]
        funding = []
        for i, ((_, _, owner), profile) in enumerate(zip(keys, (False, True, "scheduled"), strict=True)):
            lock = script(locking_script_from_owner_hash(owner, compiled_curve=profile))
            funding.append(Tx(2, [TxIn(f"{i + 51:02x}" * 32, 0, Script())],
                              [TxOut(1, P2PKH), TxOut(1000, lock)], 0))
        inputs = [TxIn(prev.id(), 1, Script(), 0xfffffffe - i) for i, prev in enumerate(funding)]
        scheduled = script(locking_script_from_owner_hash(bytes(range(20)), compiled_curve="scheduled"))
        compiled = script(locking_script_from_owner_hash(bytes(reversed(range(20))), compiled_curve=True))
        layouts = (
            (compiled, P2PKH, scheduled, compiled, scheduled),
            (scheduled, compiled),
        )
        with TemporaryDirectory() as temp:
            history = Path(temp) / "history.db"
            for version in (1, 2):
                for locks in layouts:
                    outputs = [TxOut(500 - i, lock) for i, lock in enumerate(locks)]
                    tx = Tx(version, inputs, outputs, 17)
                    for flag in modes:
                        with self.subTest(version=version, mode=hex(flag), shape=(len(inputs), len(locks))):
                            signed = self.sign_reconstruction_case(tx, funding, keys, flag, history)
                            self.check_chronicle(signed, funding, push_only=version == 1)
                            if version == 2 and len(locks) == 5 and flag & 0x20:
                                self.check_otda_output_scope(signed, funding, flag)

    def sign_reconstruction_case(self, tx, funding, keys, flag, history):
        wire = Transaction.parse(tx.serialize())
        signed_inputs = []
        is_otda_single = flag in (0x63, 0xe3)
        for i, (prev, (key, public, _)) in enumerate(zip(funding, keys, strict=True)):
            approvals = []

            def callback(digest):
                signature = fixture_signature(key, digest)
                approvals.append((digest, signature))
                return signature

            original = tx.tx_ins[i]
            amount = prev.tx_outs[original.prev_index].amount
            witness = sign_spend(tx, i, prev, flag, public, callback, history, compress_otda="paired")
            companion = is_otda_single and i >= len(wire.outputs)
            if flag & 0x20 and not companion:
                preimage = preimage_otda(wire, i, bytes.fromhex("68ac"), flag)
            else:
                code = bytes.fromhex("63ad67ab68ac" if companion else "68ac")
                preimage = preimage_forkid(wire, i, amount, code, flag & ~0x20)
            (digest, signature), = approvals
            self.assertEqual(digest, hash256(preimage), i)
            auth = authorization(tx, i, amount, flag)
            literal = current_input_unlock(auth, public, signature).raw_serialize()
            raw = witness.raw_serialize()
            stack, alt = evaluate(raw)
            self.assertEqual(stack[0], preimage, i)
            self.assertEqual((stack, alt), evaluate(literal), i)
            compresses = flag in (0x61, 0xe1) or (
                is_otda_single and not companion and wire.outputs[i].script != P2PKH.raw_serialize()
            )
            if tx.version == 2 and compresses:
                self.assertLess(len(raw), len(literal), i)
            else:
                self.assertEqual(raw, literal, i)
            signed_inputs.append(TxIn(original.prev_tx, original.prev_index, witness, original.sequence))
        return Tx(tx.version, signed_inputs, tx.tx_outs, tx.locktime)

    def check_otda_output_scope(self, signed, funding, flag):
        # Keep the transaction structurally valid in each case and change one
        # class of signed output bytes at a time.
        original = signed.tx_outs
        changed_lock = script(locking_script_from_owner_hash(bytes([17]) * 20, compiled_curve=True))
        changes = (
            ("amount", [TxOut(original[0].amount - 1, original[0].script_pubkey), *original[1:]], {0}),
            ("owner", [TxOut(original[0].amount, changed_lock), *original[1:]], {0}),
            ("order", [original[2], original[1], original[0], *original[3:]], {0, 2}),
            ("unpaired output", [*original[:-1], TxOut(original[-1].amount - 1, original[-1].script_pubkey)],
             {len(original) - 1}),
        )
        for field, outputs, changed in changes:
            with self.subTest(field=field):
                tx = Tx(signed.version, signed.tx_ins, outputs, signed.locktime)
                base = flag & 31
                accepted = [base == 2 or (base == 3 and i not in changed) for i in range(len(funding))]
                if all(accepted):
                    tx.validate_at_height(funding, CHRONICLE_MAINNET_HEIGHT, "BSV_Mainnet")
                else:
                    with self.assertRaises(ValueError):
                        tx.validate_at_height(funding, CHRONICLE_MAINNET_HEIGHT, "BSV_Mainnet")
                for i, valid in enumerate(accepted):
                    check(tx, funding, i, valid=valid)

    def test_mixed_all_reconstructs_two_templates_and_measures_marginals(self):
        keys, locks, funding = self.funding(compiled_curve="scheduled")
        old = script(locking_script_from_owner_hash(keys[4][2], compiled_curve=True))
        outputs = [locks[3], old, locks[5]]
        shapes = ((2, 2), (3, 2), (2, 3))
        sizes = {
            0x61: ((195028, 110302), (245743, 118654), (243821, 156695)),
            0xe1: ((194944, 110218), (245494, 118405), (243737, 156611)),
        }
        for flag, expected_sizes in sizes.items():
            for (m, n), expected in zip(shapes, expected_sizes, strict=True):
                with self.subTest(flag=hex(flag), inputs=m, outputs=n):
                    prev = funding[:m]
                    tx = Tx(2, [TxIn(p.id(), 0, Script()) for p in prev],
                            [TxOut(500, lock) for lock in outputs[:n]], 0)
                    with patch("signature.reconstruct_mixed", return_value=None):
                        single_dictionary = self.sign(tx, prev, keys[:m], flag, compress="paired")
                    mixed = self.sign(tx, prev, keys[:m], flag, compress="paired")
                    self.check_chronicle(mixed, prev)
                    self.assertEqual((len(single_dictionary.serialize()), len(mixed.serialize())), expected)
                    for before, after in zip(single_dictionary.tx_ins, mixed.tx_ins, strict=True):
                        self.assertEqual(evaluate(before.script_sig.raw_serialize()),
                                         evaluate(after.script_sig.raw_serialize()))

    def test_paired_profile_falls_back_for_version_one_and_literal_outputs(self):
        keys, locks, funding = self.funding(compiled_curve="scheduled")
        prev = funding[:2]
        for version, outputs in ((1, locks[3:5]), (2, [P2PKH, P2PKH])):
            for flag in (0x63, 0xe3):
                with self.subTest(version=version, flag=hex(flag)):
                    tx = Tx(version, [TxIn(p.id(), 0, Script()) for p in prev],
                            [TxOut(500, lock) for lock in outputs], 0)
                    literal = self.sign(tx, prev, keys[:2], flag, compress=False)
                    compact = self.sign(tx, prev, keys[:2], flag, compress="paired")
                    self.assertEqual(compact.serialize(), literal.serialize())
                    self.check_chronicle(compact, prev, push_only=version == 1)

    def test_otda_reconstruction_preserves_the_preimage_and_output_binding(self):
        keys, locks, funding = self.funding()
        prev = funding[:2]
        outputs = [TxOut(700, P2PKH), TxOut(850, locks[3])]
        unsigned = Tx(2, [TxIn(p.id(), 0, Script()) for p in prev], outputs, 7)
        for flag in (0x61, 0xe1):
            compact = self.sign(unsigned, prev, keys[:2], flag, compress=True)
            literal = self.sign(unsigned, prev, keys[:2], flag, compress=False)
            self.check_chronicle(compact, prev)
            self.assertLess(len(compact.serialize()), len(literal.serialize()))
            for i, (large, small) in enumerate(zip(literal.tx_ins, compact.tx_ins, strict=True)):
                raw_stack, raw_alt = evaluate(large.script_sig.raw_serialize())
                packed_stack, packed_alt = evaluate(small.script_sig.raw_serialize())
                independent = preimage_otda(Transaction.parse(unsigned.serialize()), i, b"\x68\xac", flag)
                self.assertEqual(len(raw_stack), 5)
                self.assertEqual(raw_stack[0], independent)
                self.assertEqual((packed_stack, packed_alt), (raw_stack, raw_alt))
            changed_outputs = (
                [TxOut(699, P2PKH), outputs[1]],
                [outputs[1], outputs[0]],
                [outputs[0], TxOut(850, locks[4])],
            )
            for changed in changed_outputs:
                signed = Tx(2, compact.tx_ins, changed, compact.locktime)
                with self.assertRaises(ValueError):
                    signed.validate_at_height(prev, CHRONICLE_MAINNET_HEIGHT, "BSV_Mainnet")
                for i in range(len(prev)):
                    check(signed, prev, i, valid=False)

    def test_shared_kernel_program_preserves_signature_and_exact_preimage(self):
        keys, locks, funding = self.funding()
        inputs = [TxIn(parent.id(), 0, Script()) for parent in funding[:2]]
        template = compiled_template()
        _, program = otda_reconstruction(shared_kernels=True)
        _, original = otda_reconstruction()
        self.assertEqual(len(program), 3921)
        self.assertEqual(evaluate(program), (
            [template.script[:template.owner_start], template.script[template.owner_end:]], [],
        ))
        for flag, outputs in ((0x61, [locks[3], locks[4]]), (0xe1, [P2PKH, locks[4]])):
            with self.subTest(flag=hex(flag)):
                tx = Tx(2, inputs, [TxOut(750, lock) for lock in outputs], 0)
                legacy = self.sign(tx, funding[:2], keys[:2], flag, compress=True)
                compact = self.sign(tx, funding[:2], keys[:2], flag, compress="shared-kernels")
                self.check_chronicle(compact, funding[:2])
                self.assertEqual(len(legacy.serialize()) - len(compact.serialize()),
                                 len(inputs) * (len(original) - len(program)))
                for old, new in zip(legacy.tx_ins, compact.tx_ins, strict=True):
                    self.assertEqual(evaluate(old.script_sig.raw_serialize()),
                                     evaluate(new.script_sig.raw_serialize()))

    def test_mode_specific_size_experiments_preserve_their_declared_modes(self):
        key, public, owner = signer(3)
        # The existing check verifies the selected input. A trivial sponsor
        # keeps the complete chain-gang transaction independent of this lock.
        sponsor = parent(Script.parse_string("OP_1"), 100, "22")
        for family in ("forkid", "otda"):
            raw = specialized_lock(owner, family)
            self.assertLess(len(raw), len(compiled_template().script))
            funding = parent(script(raw), 1000, "33")
            previous = [sponsor, funding]
            for paired in (False, True):
                flags = UNIVERSAL_FLAGS if paired else (0x43, 0xc3, 0x63, 0xe3)
                for flag in flags:
                    with self.subTest(family=family, paired=paired, sighash=hex(flag)):
                        outputs = [300, 700] if paired else [1000]
                        unsigned = child(previous, outputs)
                        auth = authorization(unsigned, 1, 1000, flag)
                        witness = current_input_unlock(auth, public, fixture_signature(key, auth.digest()))
                        signed = child(previous, outputs, {1: witness})
                        expected = bool(flag & 0x20) == (family == "otda")
                        check(signed, previous, 1, valid=expected)
                        check(signed, previous, 1, valid=expected and family == "forkid",
                              chronicle=False, funding_height=1)
                        if expected:
                            signed.validate(previous)
                        else:
                            with self.assertRaises((ValueError, RuntimeError)):
                                signed.validate(previous)

    def test_original_unlock_fallback(self):
        keys, locks, funding = self.funding()
        for flag, version, outputs in (
            (0x61, 1, [locks[3], locks[4]]),
            (0x61, 2, [P2PKH, P2PKH]),
            (0x62, 2, [locks[3], locks[4]]),
            (0x63, 2, [locks[3], locks[4]]),
            (0xe3, 2, [locks[3]]),
        ):
            with self.subTest(flag=hex(flag), version=version, outputs=len(outputs)):
                prev = funding[:2]
                unsigned = Tx(version, [TxIn(p.id(), 0, Script()) for p in prev],
                              [TxOut(900, x) for x in outputs], 0)
                literal = self.sign(unsigned, prev, keys[:2], flag, compress=False)
                for profile in (True, "shared-kernels"):
                    optional = self.sign(unsigned, prev, keys[:2], flag, compress=profile)
                    self.assertEqual(optional.serialize(), literal.serialize())
                    self.check_chronicle(optional, prev, push_only=version == 1)

    @staticmethod
    def funding(*, compiled_curve=True):
        keys = [signer(i) for i in range(1, 7)]
        locks = [script(locking_script_from_owner_hash(owner, compiled_curve=compiled_curve)) for _, _, owner in keys]
        return keys, locks, [parent(lock, 1000, f"{i+31:02x}") for i, lock in enumerate(locks[:3])]

    @staticmethod
    def sign(unsigned, funding, keys, flag, *, compress):
        inputs = []
        with TemporaryDirectory() as temp:
            history = Path(temp) / "history.db"
            for i, (previous, (key, public, _)) in enumerate(zip(funding, keys, strict=True)):
                unlock = sign_spend(unsigned, i, previous, flag, public,
                                    lambda digest: fixture_signature(key, digest), history, compress_otda=compress)
                inputs.append(TxIn(previous.id(), 0, unlock))
        return Tx(unsigned.version, inputs, unsigned.tx_outs, unsigned.locktime)

    @staticmethod
    def check_chronicle(tx, funding, *, push_only=False):
        tx.validate_at_height(funding, CHRONICLE_MAINNET_HEIGHT, "BSV_Mainnet")
        for i in range(len(funding)):
            check(tx, funding, i, extra_flags=(1 << 5) if push_only else 0)

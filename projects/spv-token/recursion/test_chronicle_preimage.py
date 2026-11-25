from dataclasses import replace
import unittest

from chronicle_preimage import CHRONICLE_ALL, LEGACY_ALL, normalize_shared_verifier_preimage
from shared.transaction import Input, Output, Transaction, blob, compact, hash256, preimage_forkid, preimage_otda

LEGACY_CODE = b"\x51\xac"
CHRONICLE_CODE = b"\x52\xac"


class ChroniclePreimageTests(unittest.TestCase):
    def setUp(self):
        self.funding = Transaction((Input(b"f" * 32, 0),),
                                   (Output(9, b"\x51"), Output(451, b"original verifier lock")))
        self.index = 1
        self.tx = Transaction((
            Input(b"a" * 32, 1, b"first holder signature", sequence=31),
            Input(self.funding.txid_wire(), 1, b"shared verifier witness", sequence=511),
            Input(b"b" * 32, 7, b"other holder signature", sequence=126),
        ), (Output(76, b"\x51"), Output(182, b"z" * 253)), version=2, locktime=458)

    def normalizer(self, preimage, sighash_type, script_code, *, tx=None, funding=None, index=None):
        return normalize_shared_verifier_preimage(
            self.tx if tx is None else tx, self.index if index is None else index,
            self.funding if funding is None else funding, preimage,
            sighash_type=sighash_type, script_code=script_code,
        )

    def test_two_branches_derive_common_transaction_fields(self):
        for version in (1, 2):
            with self.subTest(version=version):
                tx = replace(self.tx, version=version)
                forkid = preimage_forkid(tx, self.index, 451, LEGACY_CODE, LEGACY_ALL)
                otda = preimage_otda(tx, self.index, CHRONICLE_CODE, CHRONICLE_ALL)
                legacy = self.normalizer(forkid, LEGACY_ALL, LEGACY_CODE, tx=tx)
                chronicle = self.normalizer(otda, CHRONICLE_ALL, CHRONICLE_CODE, tx=tx)
                self.assertNotEqual(legacy.digest, chronicle.digest)
                self.assertEqual(legacy.digest, hash256(forkid))
                self.assertEqual(chronicle.digest, hash256(otda))
                self.assertEqual(replace(legacy, digest=chronicle.digest, sighash_type=chronicle.sighash_type),
                                 chronicle)
                self.assertEqual(chronicle.version, version)
                self.assertEqual(chronicle.prevouts, b"".join(item.outpoint() for item in tx.inputs))
                self.assertEqual(chronicle.hash_prevouts, forkid[4:36])
                self.assertEqual(chronicle.hash_sequence, forkid[36:68])
                self.assertEqual(chronicle.current_outpoint, tx.inputs[self.index].outpoint())
                self.assertEqual(chronicle.current_sequence, 511)
                self.assertEqual(chronicle.previous_amount, 451)
                self.assertEqual(chronicle.outputs, b"".join(item.serialize() for item in tx.outputs))
                self.assertEqual(chronicle.hash_outputs, forkid[-40:-8])
                self.assertEqual(chronicle.locktime, 458)

    def test_rejects_branch_confusion_and_unapproved_signature_types(self):
        forkid = preimage_forkid(self.tx, self.index, 451, LEGACY_CODE, LEGACY_ALL)
        otda = preimage_otda(self.tx, self.index, CHRONICLE_CODE, CHRONICLE_ALL)
        for raw, branch, code in (
            (forkid, CHRONICLE_ALL, LEGACY_CODE), (otda, LEGACY_ALL, CHRONICLE_CODE),
            (forkid[:-4] + CHRONICLE_ALL.to_bytes(4, "little"), CHRONICLE_ALL, LEGACY_CODE),
            (otda[:-4] + LEGACY_ALL.to_bytes(4, "little"), LEGACY_ALL, CHRONICLE_CODE),
            (forkid, LEGACY_ALL, CHRONICLE_CODE), (otda, CHRONICLE_ALL, LEGACY_CODE),
        ):
            with self.subTest(branch=branch, code=code), self.assertRaisesRegex(ValueError, "does not match"):
                self.normalizer(raw, branch, code)
        for branch in (0x43, 0x63, 0xC1, 0xE1, True):
            with self.subTest(branch=branch), self.assertRaisesRegex(ValueError, "signature type"):
                self.normalizer(forkid, branch, LEGACY_CODE)

    def test_otda_uses_exact_current_scriptcode_and_canonical_complete_wire(self):
        raw = preimage_otda(self.tx, self.index, CHRONICLE_CODE, CHRONICLE_ALL)
        other_input_script = 5 + 36
        selected_input_script = 5 + 41 + 36
        output_count = 5 + 41 + (41 + len(CHRONICLE_CODE)) + 41
        candidates = (
            raw[:4] + b"\xfd\x03\x00" + raw[5:],
            raw[:other_input_script] + blob(b"\x51") + raw[other_input_script + 1:],
            raw[:selected_input_script] + b"\xfd\x02\x00" + raw[selected_input_script + 1:],
            raw[:output_count] + b"\xfd\x02\x00" + raw[output_count + 1:],
            raw[:-8] + b"x" + raw[-8:],
            raw[:-1],
            raw + b"x",
        )
        for candidate in candidates:
            with self.subTest(size=len(candidate)), self.assertRaisesRegex(ValueError, "does not match"):
                self.normalizer(candidate, CHRONICLE_ALL, CHRONICLE_CODE)
        for tx in (
            replace(self.tx, version=1),
            replace(self.tx, locktime=459),
            replace(self.tx, outputs=self.tx.outputs[::-1]),
            replace(self.tx, inputs=(self.tx.inputs[2], self.tx.inputs[1], self.tx.inputs[0])),
            replace(self.tx, inputs=(replace(self.tx.inputs[0], sequence=32), *self.tx.inputs[1:])),
            replace(self.tx, inputs=(self.tx.inputs[0], replace(self.tx.inputs[1], sequence=1), self.tx.inputs[2])),
        ):
            with self.assertRaisesRegex(ValueError, "does not match"):
                self.normalizer(raw, CHRONICLE_ALL, CHRONICLE_CODE, tx=tx)

    def test_funding_is_checked_independently_in_both_paths(self):
        forkid = preimage_forkid(self.tx, self.index, 451, LEGACY_CODE, LEGACY_ALL)
        fake_amount = preimage_forkid(self.tx, self.index, 452, LEGACY_CODE, LEGACY_ALL)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.normalizer(fake_amount, LEGACY_ALL, LEGACY_CODE)

        otda = preimage_otda(self.tx, self.index, CHRONICLE_CODE, CHRONICLE_ALL)
        changed = replace(self.funding, outputs=(self.funding.outputs[0],
                                                 replace(self.funding.outputs[1], value=452)))
        for raw, kind, code in ((forkid, LEGACY_ALL, LEGACY_CODE), (otda, CHRONICLE_ALL, CHRONICLE_CODE)):
            with self.assertRaisesRegex(ValueError, "funding outpoint"):
                self.normalizer(raw, kind, code, funding=changed)
        old_vin = self.tx.inputs[self.index]
        new_vin = replace(old_vin, txid=changed.txid_wire())
        new_tx = replace(self.tx, inputs=(self.tx.inputs[0], new_vin, self.tx.inputs[2]))
        fresh = preimage_otda(new_tx, self.index, CHRONICLE_CODE, CHRONICLE_ALL)
        self.assertEqual(self.normalizer(fresh, CHRONICLE_ALL, CHRONICLE_CODE, tx=new_tx,
                                         funding=changed).previous_amount, 452)
        wrong_vout = replace(new_tx, inputs=(self.tx.inputs[0], replace(new_vin, vout=2), self.tx.inputs[2]))
        with self.assertRaisesRegex(ValueError, "funding outpoint"):
            self.normalizer(fresh, CHRONICLE_ALL, CHRONICLE_CODE, tx=wrong_vout, funding=changed)
        with self.assertRaisesRegex(ValueError, "input position"):
            self.normalizer(fresh, CHRONICLE_ALL, CHRONICLE_CODE, index=-1)

    def test_compactsize_boundaries_and_otda_excludes_unlocking_scripts(self):
        carriers = tuple(Input(bytes([i % 256]) * 32, i, b"holder witness") for i in range(253))
        tx = replace(self.tx, inputs=(*carriers, self.tx.inputs[self.index]),
                     outputs=(Output(1, bytes(253)),) * 253)
        verifier_index = len(carriers)
        script_code = b"\x51" * 253
        raw = preimage_otda(tx, verifier_index, script_code, CHRONICLE_ALL)
        self.assertEqual(raw[4:7], compact(254))
        result = self.normalizer(raw, CHRONICLE_ALL, script_code, tx=tx, index=verifier_index)
        self.assertEqual(len(result.prevouts), 254 * 36)
        self.assertEqual(result.outputs, Output(1, bytes(253)).serialize() * 253)
        changed = tx.with_script(0, b"different unrelated witness").with_script(verifier_index, b"new witness")
        self.assertEqual(self.normalizer(raw, CHRONICLE_ALL, script_code, tx=changed,
                                         index=verifier_index), result)


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from handwritten import _template, flags_for, locking_script, replace_owner_hash160
from lock_identity import identify_locking_script, matches_owner_key


def public(curve, form):
    return ec.derive_private_key(19, curve).public_key().public_bytes(serialization.Encoding.X962, form)


def h160(raw):
    return hashlib.new("ripemd160", hashlib.sha256(raw).digest()).digest()


class LockIdentityTests(unittest.TestCase):
    def test_standard_templates(self):
        for form in (serialization.PublicFormat.CompressedPoint, serialization.PublicFormat.UncompressedPoint):
            key = public(ec.SECP256K1(), form)
            p2pk = bytes([len(key)]) + key + b"\xac"
            p2pkh = b"\x76\xa9\x14" + h160(key) + b"\x88\xac"
            for raw, kind in ((p2pk, "P2PK"), (p2pkh, "P2PKH")):
                result = identify_locking_script(raw)
                self.assertEqual((result.script_type, result.curve), (kind, "secp256k1"))
                self.assertEqual(result.owner_public_key, key if kind == "P2PK" else None)
                self.assertEqual(result.owner_hash160, h160(key) if kind == "P2PKH" else None)
                self.assertTrue(matches_owner_key(result, key))
                self.assertFalse(matches_owner_key(result, bytes(32)))
                self.assertIsNone(identify_locking_script(raw + b"\x00"))
                self.assertIsNone(identify_locking_script(raw[1:]))
            self.assertIsNone(identify_locking_script(key))

    def test_r1_versions_and_helper_key(self):
        key = public(ec.SECP256R1(), serialization.PublicFormat.UncompressedPoint)
        helper = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        for version in range(1, 9):
            flags = tuple(flags_for(version))
            raw = locking_script(h160(key), flags, version=version).raw_serialize()
            result = identify_locking_script(raw)
            self.assertEqual((result.script_type, result.curve, result.template_version), ("P2PKH-R1", "secp256r1", version))
            self.assertEqual(result.owner_hash160, h160(key))
            self.assertIsNone(result.owner_public_key)
            self.assertEqual(set(result.allowed_types), set(flags))
            self.assertTrue(matches_owner_key(result, key))
            self.assertFalse(matches_owner_key(result, helper))
            self.assertIn(helper, raw)
            self.assertIsNone(identify_locking_script(raw[:-1] + b"\x51"))
            self.assertIsNone(identify_locking_script(raw + bytes(32)))

    def test_v7_prefilter_and_binary_capture(self):
        owner = bytes([0, 10, 20, 33, 65, 76, 135, 172, 255, 1]) * 2
        raw = locking_script(owner, (0x41, 0x63), version=7).raw_serialize()
        self.assertEqual(len(raw), 59811)
        self.assertTrue(raw.startswith(bytes.fromhex("760052a5696b8201209d")))
        self.assertEqual(identify_locking_script(raw).owner_hash160, owner)
        changed = replace_owner_hash160(raw, bytes(reversed(owner)))
        self.assertEqual(identify_locking_script(changed).allowed_types, (0x41, 0x63))
        _, offset, _ = _template(7)
        self.assertEqual(raw[offset:offset+20], owner)
        print(f"v7 owner HASH160 starts at byte {offset}, script size {len(raw)}")
        self.assertIsNone(identify_locking_script(raw[:10]))
        self.assertIsNone(identify_locking_script(raw[:-2] + bytes(2)))

    def test_reject_non_owner_material(self):
        # Local dummy scalar, never an input to the application's signing API.
        temporary = (23).to_bytes(32, "big")
        dummy_key = ec.derive_private_key(23, ec.SECP256R1())
        private_der = dummy_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption())
        raw_r1_key = public(ec.SECP256R1(), serialization.PublicFormat.UncompressedPoint)
        cases = [temporary, temporary.hex().encode(), private_der,
                 b"\x20" + temporary + b"\xac",  # PUSH32 is not P2PK
                 b"\x41\x04" + bytes(64) + b"\xac",  # invalid public point
                 b"\x4c\x41" + raw_r1_key + b"\xac",
                 b"\x6a\x20" + temporary, b"\x21" + b"\x05" + temporary + b"\xac"]
        lock = identify_locking_script(locking_script(h160(raw_r1_key), version=7).raw_serialize())
        for item in cases:
            self.assertIsNone(identify_locking_script(item))
            self.assertFalse(matches_owner_key(lock, item))

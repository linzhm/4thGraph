"""Verify the public CLI at the same boundary as an integrating wallet."""
from hashlib import new, sha256
import json
from pathlib import Path
import subprocess
import sys
import unittest

from handwritten import locking_script
from lock_identity import identify_locking_script
from p2pkh_r1 import locking_script_from_public_key, public_key_hash160, recognize, recognize_ordinary


CLI = Path(__file__).with_name("generate_lock.py")
# SEC 2 P-256 generator, used solely as a public encoding fixture.
PUBLIC = ("04"
          "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
          "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


def run_cli(*args):
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True)


class GenerateLockTest(unittest.TestCase):
    def test_assembly_from_both_public_forms(self):
        owner = new("ripemd160", sha256(bytes.fromhex(PUBLIC)).digest()).hexdigest()
        generated = run_cli("--public-key", PUBLIC, "--format", "raw")
        self.assertEqual(generated.returncode, 0, generated.stderr)
        equivalent = run_cli("--owner-hash160", owner, "--format", "raw")
        self.assertEqual(equivalent.returncode, 0, equivalent.stderr)
        self.assertEqual(generated.stdout, equivalent.stdout)
        manifest = run_cli("--owner-hash160", owner)
        self.assertEqual(manifest.returncode, 0, manifest.stderr)
        self.assertEqual(json.loads(manifest.stdout), {
            "template": "P2PKH-R1", "version": 7, "owner_hash160": owner,
            "allowed_types": ["41", "42", "43", "61", "62", "63", "c1", "c2", "c3", "e1", "e2", "e3"],
            "script_bytes": 59811,
            "script_sha256": sha256(generated.stdout).hexdigest(),
        })
        custom = run_cli("--owner-hash160", owner, "--allow", "42,e3", "--format", "raw")
        self.assertEqual(custom.returncode, 0, custom.stderr)
        self.assertEqual(set(identify_locking_script(custom.stdout).allowed_types), {0x42, 0xe3})
        self.assertNotEqual(custom.stdout, generated.stdout)

    def test_rejected_arguments_produce_no_script(self):
        for args in [
            ["--public-key", "04" + "00" * 64], ["--public-key", "12" * 32],
            ["--owner-hash160", "12" * 32], ["--owner-hash160", "00" * 20, "--allow", "01"],
            ["--owner-hash160", "00" * 20, "--allow", ""],
            ["--owner-hash160", "00" * 20, "--public-key", PUBLIC],
        ]:
            with self.subTest(arguments=args[::2]):
                result = run_cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_portable_receiving_vectors(self):
        directory = CLI.parents[2] / "docs/research/p2pkh-r1"
        metadata = json.loads((directory / "layout.json").read_text())
        base = bytes.fromhex((directory / metadata["base_script_hex_file"]).read_text())
        self.assertEqual(sha256(base).hexdigest(), metadata["base_script_sha256"])
        slots = metadata["sighash_offsets"]
        owner = metadata["owner_hash160"]
        variable = set(slots.values()) | set(range(owner["offset"], owner["offset"] + owner["length"]))
        fixed = bytes(value for i, value in enumerate(base) if i not in variable)
        self.assertEqual(len(fixed), metadata["fixed_bytes_length"])
        self.assertEqual(sha256(fixed).hexdigest(), metadata["fixed_bytes_sha256"])
        self.assertEqual(metadata["ordinary_fixed_bytes_length"], len(base) - owner["length"])
        ordinary = base[:owner["offset"]] + base[owner["offset"] + owner["length"]:]
        self.assertEqual(sha256(ordinary).hexdigest(), metadata["ordinary_fixed_bytes_sha256"])
        self.assertTrue(base.startswith(bytes.fromhex(metadata["prefix_hex"])))
        for vector in metadata["vectors"]:
            owner_hash = bytes.fromhex(vector["owner_hash160"])
            flags = tuple(int(t, 16) for t in vector["allowed_types"])
            assembled = locking_script(owner_hash, flags, version=7).raw_serialize()
            self.assertEqual(len(assembled), metadata["script_bytes"])
            self.assertEqual(sha256(assembled).hexdigest(), vector["script_sha256"])
            self.assertEqual(recognize(assembled).owner_hash160, owner_hash)
            self.assertEqual(set(recognize(assembled).allowed_types), set(flags))
            if "public_key_x963" in vector:
                q = bytes.fromhex(vector["public_key_x963"])
                self.assertEqual(public_key_hash160(q), owner_hash)
                self.assertEqual(recognize_ordinary(assembled), owner_hash)
                self.assertEqual(assembled, locking_script(owner_hash, version=7).raw_serialize())
                self.assertEqual(locking_script_from_public_key(q), assembled)
                self.assertEqual(locking_script_from_public_key(q, reversed(flags)), assembled)

    def test_fixed_digest_and_policy_boundaries(self):
        q = bytes.fromhex(PUBLIC)
        base = locking_script_from_public_key(q)
        for i in (0, 100, 306, 308, 436, 457, len(base) - 1):
            changed = bytearray(base)
            changed[i] ^= 1
            self.assertIsNone(recognize(bytes(changed)))
            self.assertIsNone(recognize_ordinary(bytes(changed)))
        for flags in ((0x42,), (0xe3,), (0xc1, 0x61, 0x43)):
            raw = locking_script_from_public_key(q, flags)
            self.assertIsNone(recognize_ordinary(raw))
            self.assertEqual(set(recognize(raw).allowed_types), set(flags))
            self.assertEqual(raw, locking_script(public_key_hash160(q), flags, version=7).raw_serialize())
        disabled = bytearray(locking_script_from_public_key(q, (0x41, 0x61)))
        disabled[307] = disabled[366] = 0
        self.assertIsNone(recognize(bytes(disabled)))
        disabled[307] = 1
        self.assertIsNone(recognize(bytes(disabled)))
        for invalid in (q[1:], b"\x04" + bytes(64), bytes(32)):
            with self.assertRaises(ValueError):
                locking_script_from_public_key(invalid)

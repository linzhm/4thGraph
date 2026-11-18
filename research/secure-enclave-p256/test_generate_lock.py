"""Verify the public CLI at the same boundary as an integrating wallet."""
from hashlib import new, sha256
import json
from pathlib import Path
import subprocess
import sys
import unittest

from handwritten import UNIVERSAL_FLAGS, locking_script
from lock_identity import identify_locking_script
from p2pkh_r1 import locking_script_from_public_key, recognize


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
            "template": "P2PKH-R1", "owner_hash160": owner, "script_bytes": 59582,
            "script_sha256": sha256(generated.stdout).hexdigest(),
        })
        self.assertEqual(generated.stdout, locking_script_from_public_key(bytes.fromhex(PUBLIC)))
        lock = identify_locking_script(generated.stdout)
        self.assertEqual(set(lock.allowed_types), set(UNIVERSAL_FLAGS))


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

    def test_portable_vectors_and_program_fingerprint(self):
        directory = CLI.parents[2] / "docs/research/p2pkh-r1-current-input"
        layout = json.loads((directory / "layout.json").read_text())
        base = bytes.fromhex((directory / layout["base_script_hex_file"]).read_text())
        start = layout["owner_hash160"]["offset"]
        end = start + layout["owner_hash160"]["length"]
        fixed = base[:start] + base[end:]
        self.assertEqual(len(fixed), layout["fixed_bytes_length"])
        self.assertEqual(sha256(fixed).hexdigest(), layout["fixed_bytes_sha256"])
        self.assertEqual(sha256(base).hexdigest(), layout["base_script_sha256"])
        self.assertTrue(base.startswith(bytes.fromhex(layout["prefix_hex"])))
        self.assertEqual({int(f, 16) for f in layout["supported_sighash_types"]}, set(UNIVERSAL_FLAGS))
        for vector in layout["vectors"]:
            owner = bytes.fromhex(vector["owner_hash160"])
            assembled = locking_script(owner, version=9).raw_serialize()
            self.assertEqual(assembled, base[:start] + owner + base[end:])
            self.assertEqual(len(assembled), layout["script_bytes"])
            self.assertEqual(sha256(assembled).hexdigest(), vector["script_sha256"])
            self.assertEqual(recognize(assembled), owner)
            if "public_key_x963" in vector:
                self.assertEqual(locking_script_from_public_key(bytes.fromhex(vector["public_key_x963"])), assembled)
        for i in (0, 100, start - 1, end, len(base) - 1):
            changed = bytearray(base)
            changed[i] ^= 1
            self.assertIsNone(recognize(bytes(changed)))
        self.assertIsNone(recognize(base + b"0"))
        self.assertIsNone(recognize(base[:-1]))
        with self.assertRaises(ValueError):
            locking_script(bytes(20), (0x41,), version=9)

"""Verify the public CLI at the same boundary as an integrating wallet."""
from hashlib import new, sha256
import json
from pathlib import Path
import subprocess
import sys
import unittest

from lock_identity import identify_locking_script


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
        equivalent = run_cli("--owner-hash160", owner, "--allow", "61,41", "--format", "raw")
        self.assertEqual(equivalent.returncode, 0, equivalent.stderr)
        self.assertEqual(generated.stdout, equivalent.stdout)
        manifest = run_cli("--owner-hash160", owner)
        self.assertEqual(manifest.returncode, 0, manifest.stderr)
        self.assertEqual(json.loads(manifest.stdout), {
            "template": "P2PKH-R1", "version": 7, "owner_hash160": owner,
            "allowed_types": ["41", "61"], "script_bytes": 59811,
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

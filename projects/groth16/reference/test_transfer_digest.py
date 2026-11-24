"""Cross-check the compact transfer digest in Circom and Python."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from shared.transaction import Input, Output, Transaction
from transfer import COMPACT_SUFFIX, TransferStatement

CIRCUITS = Path(__file__).resolve().parents[1] / "circuits"


@unittest.skipUnless(shutil.which("circom") and shutil.which("node"), "requires Circom and Node")
class TransferDigestTests(unittest.TestCase):
    def test_actual_forkid_preimage(self):
        from circom_fixture_prover import CompiledProver
        from verifier import verify_host

        lock = b"\x51" + COMPACT_SUFFIX
        funding = Transaction((Input(b"\xaa" * 32, 1),), (Output(1000, lock),))
        tx = Transaction((Input(funding.txid_wire(), 0),), (Output(900, b"\x51"),))
        issuance = bytes(range(36))
        statement = TransferStatement(issuance, lock, compact_preimage=True)
        preimage = statement.preimage(tx, 0, funding)
        high, low = statement.public_inputs(tx, 0, funding)
        self.assertEqual(len(preimage), 192)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in ("mimo_relation.circom", "sha256_bytes.circom", "transfer_digest.circom"):
                shutil.copyfile(CIRCUITS / source, root / source)
            (root / "check.circom").write_text(
                'pragma circom 2.2.3;\ninclude "transfer_digest.circom";\n'
                'component main {public [digestHigh, digestLow]} = CompactTransferDigest();\n'
            )
            build = subprocess.run(["circom", "check.circom", "--r1cs", "--wasm", "--prime", "bls12381"],
                                   cwd=root, capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)

            def generate(raw, expected):
                (root / "input.json").write_text(json.dumps({
                    "preimage": list(raw), "issuance": list(issuance),
                    "digestHigh": str(expected[0]), "digestLow": str(expected[1]),
                }))
                return subprocess.run([
                    "node", "check_js/generate_witness.js", "check_js/check.wasm", "input.json", "result.wtns",
                ], cwd=root, capture_output=True, text=True)

            valid = generate(preimage, (high, low))
            self.assertEqual(valid.returncode, 0, valid.stderr)
            prover = CompiledProver.load(root / "check.r1cs")
            signals, proof = prover.prove(root / "result.wtns")
            self.assertEqual(signals, (high, low))
            self.assertTrue(verify_host(prover.key, signals, proof))
            modified = bytearray(preimage)
            modified[152] ^= 1  # hashOutputs
            invalid = generate(modified, (high, low))
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("Assert Failed", invalid.stderr)

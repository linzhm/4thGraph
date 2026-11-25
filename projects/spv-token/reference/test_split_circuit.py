from dataclasses import replace
from importlib.util import find_spec
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from circom_fixture_prover import CompiledProver
from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

from shared.evaluate import ScriptError, evaluate
from shared.pushtx import PUBLIC
from shared.transaction import Input, Output, Transaction, hash256, preimage_all
from statement import TRANSFER_DOMAIN, public_inputs, transfer_bytes
from transaction_verifier import verifier_key_id, verifier_lock, verifier_witness
from transfer import COMPACT_SCRIPTCODE
from verifier import verify_host
import test_statement


@unittest.skipUnless(shutil.which("circom") and shutil.which("node"), "requires Circom and Node.js")
class SplitCircuitTests(unittest.TestCase):
    def test_python_statement_matches_circuit(self):
        project = Path(__file__).resolve().parents[1]
        fixture = test_statement.StatementTests()
        fixture.setUp()
        with TemporaryDirectory(prefix=".split-circuit-", dir=project) as directory:
            build = Path(directory)
            subprocess.run(
                ["circom", str(project / "circuits/split_commitment.circom"),
                 "--prime", "bls12381", "--r1cs", "--wasm", "-o", str(build)],
                check=True, capture_output=True, text=True,
            )
            prover = CompiledProver.load(build / "split_commitment.r1cs")
            lock = verifier_lock(fixture.asset, prover.key)
            parent = replace(fixture.parent, outputs=(Output(1, lock),))
            token_parent = Transaction((Input(b"t" * 32, 0),), (Output(2, b"\x51"),))
            tx = replace(fixture.tx, inputs=(Input(parent.txid_wire(), 0), Input(token_parent.txid_wire(), 0)))
            statement = transfer_bytes(
                fixture.asset, verifier_key_id(prover.key), tx, parent, lock,
                fixture.inputs, fixture.outputs, script_code=COMPACT_SCRIPTCODE,
            )
            preimage = preimage_all(tx, 0, 1, COMPACT_SCRIPTCODE)
            generated = build / "split_commitment_js"
            witness_input = build / "input.json"
            command = ["node", str(generated / "generate_witness.js"),
                       str(generated / "split_commitment.wasm"), str(witness_input),
                       str(build / "witness.wtns")]

            def witness(raw, digest, transaction_preimage=preimage):
                payload = raw[len(TRANSFER_DOMAIN):]
                witness_input.write_text(json.dumps({
                    "prefix": list(payload[:64]),
                    "preimage": list(transaction_preimage),
                    "inputSlots": [list(payload[98:110])],
                    "outputSlots": [list(payload[112:124]), list(payload[124:136])],
                    "digestHigh": str(digest[0]),
                    "digestLow": str(digest[1]),
                }))
                return subprocess.run(command, capture_output=True, text=True)

            expected = public_inputs(statement)
            valid = witness(statement, expected)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            signals, proof = prover.prove(build / "witness.wtns")
            self.assertEqual(signals, expected)
            self.assertTrue(verify_host(prover.key, signals, proof))
            self.assertFalse(verify_host(prover.key, signals[::-1], proof))
            altered_prefix = bytearray(statement)
            altered_prefix[len(TRANSFER_DOMAIN)] ^= 1
            self.assertIn("Assert Failed", witness(altered_prefix, public_inputs(statement)).stderr)
            changed_preimage = bytearray(preimage)
            changed_preimage[-9] ^= 1
            self.assertIn("Assert Failed", witness(statement, expected, changed_preimage).stderr)
            inflation = statement[:-8] + (385).to_bytes(8, "little")
            self.assertIn("Assert Failed", witness(inflation, public_inputs(inflation)).stderr)

            script_sig = verifier_witness(
                fixture.asset, prover.key, proof, tx, parent, fixture.inputs, fixture.outputs,
            )

            def native_signature(actual_tx):
                digest = hash256(preimage_all(actual_tx, 0, 1, COMPACT_SCRIPTCODE))

                def verify(signature, key):
                    self.assertEqual(key, PUBLIC)
                    self.assertEqual(signature[-1], 0x41)
                    signer = VerifyingKey.from_string(key, curve=SECP256k1)
                    try:
                        return signer.verify_digest(signature[:-1], digest, sigdecode=sigdecode_der)
                    except BadSignatureError:
                        return False

                return verify

            self.assertEqual(evaluate(script_sig + lock, checksig=native_signature(tx)), ([b"\x01"], []))
            changed_tx = replace(tx, outputs=tx.outputs[::-1])
            self.assertEqual(evaluate(script_sig + lock, checksig=native_signature(changed_tx)), ([b""], []))
            changed_witness = verifier_witness(
                fixture.asset, prover.key, proof, changed_tx, parent, fixture.inputs, fixture.outputs,
            )
            with self.assertRaises(ScriptError):
                evaluate(changed_witness + lock, checksig=native_signature(changed_tx))

            if find_spec("tx_engine") is not None:
                from shared.chain_gang import validate_at_heights

                validate_at_heights(tx.with_script(0, script_sig), (parent, token_parent),
                                    spend_height=100, activation_height=2, utxo_heights=(3, 3))

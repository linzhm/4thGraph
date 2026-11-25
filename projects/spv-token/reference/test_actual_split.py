from dataclasses import replace
from importlib.util import find_spec
import json
import os
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
from ecdsa import SigningKey
from regtest_mint import authorization, Node, base58check, sign_p2pkh
from shared.script import push, asm
from transaction_relation import TokenState, token_lock, bind_transfer
from split_relation_circuit import circuit_source


@unittest.skipUnless(shutil.which("circom") and shutil.which("node"), "requires Circom and Node.js")
class ActualSplitCircuitTests(unittest.TestCase):
    def test_python_statement_matches_circuit(self):
        project = Path(__file__).resolve().parents[1]
        fixture = test_statement.StatementTests()
        fixture.setUp()
        with TemporaryDirectory(prefix=".split-circuit-", dir=project) as directory:
            build = Path(directory)
            source = build / "actual_split.circom"
            source.write_text(circuit_source())
            subprocess.run(
                ["circom", str(source),
                 "--prime", "bls12381", "--r1cs", "--wasm", "-o", str(build)],
                check=True, capture_output=True, text=True,
            )
            prover = CompiledProver.load(build / "actual_split.r1cs")
            lock = verifier_lock(fixture.asset, prover.key)
            parent = replace(fixture.parent, outputs=(Output(1, lock),))
            signer = SigningKey.from_secret_exponent(11, curve=SECP256k1)  # Test-only owner.
            node = None
            carrier = 2
            verifier_value = 1
            if os.environ.get("REGTEST_COOKIE"):
                from hashlib import new, sha256
                node = Node(os.environ.get("REGTEST_URL", "http://127.0.0.1:19443"), Path(os.environ["REGTEST_COOKIE"]))
                owner_hash = new("ripemd160", sha256(signer.verifying_key.to_string("compressed")).digest()).digest()
                address = base58check(b"\x6f" + owner_hash)
                coinbase = node.fund(address)
                setup = Transaction((Input(coinbase.txid_wire(), 0),), (Output(100000000, asm("OP_1")),) * 2)
                setup = sign_p2pkh(setup, coinbase, 0, signer)
                node.confirm(setup, address)
                carrier = verifier_value = 90000000
                parent = Transaction((Input(setup.txid_wire(), 0),), (Output(verifier_value, lock),))
                node.confirm(parent, address)
            state = TokenState(fixture.asset.asset_id(), 1024, signer.verifying_key.to_string("compressed"))
            token_parent = Transaction((Input(b"t" * 32, 0),), (Output(carrier, token_lock(state, lock)),))
            if node:
                token_parent = replace(token_parent, inputs=(Input(setup.txid_wire(), 1),))
                node.confirm(token_parent, address)
            tx = replace(fixture.tx, inputs=(Input(parent.txid_wire(), 0), Input(token_parent.txid_wire(), 0)),
                         outputs=tuple(Output(1, token_lock(replace(state, quantity=q), lock)) for q in (640,384)))
            bound = bind_transfer(fixture.asset, verifier_key_id(prover.key), tx,
                                  (parent.serialize(), token_parent.serialize()), lock, fixture.inputs, fixture.outputs,
                                  authenticated_preimage=preimage_all(tx, 0, verifier_value, COMPACT_SCRIPTCODE))
            statement = transfer_bytes(
                fixture.asset, verifier_key_id(prover.key), tx, parent, lock,
                fixture.inputs, fixture.outputs, script_code=COMPACT_SCRIPTCODE,
            )
            preimage = preimage_all(tx, 0, verifier_value, COMPACT_SCRIPTCODE)
            generated = build / "actual_split_js"
            witness_input = build / "input.json"
            command = ["node", str(generated / "generate_witness.js"),
                       str(generated / "actual_split.wasm"), str(witness_input),
                       str(build / "witness.wtns")]

            def witness(raw, digest, transaction_preimage=preimage, **changes):
                payload = raw[len(TRANSFER_DOMAIN):]
                payload_json = {
                    "prefix": list(payload[:64]),
                    "preimage": list(transaction_preimage),
                    "inputSlots": [list(payload[98:110])],
                    "outputSlots": [list(payload[112:124]), list(payload[124:136])],
                    "digestHigh": str(digest[0]),
                    "digestLow": str(digest[1]),
                    "parent": list(token_parent.serialize()),
                    "prevouts": list(bound.prevouts),
                    "outputs": list(bound.outputs),
                }
                payload_json.update(changes)
                witness_input.write_text(json.dumps(payload_json))
                return subprocess.run(command, capture_output=True, text=True)

            expected = public_inputs(statement)
            self.assertEqual(bound.statement, statement)
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

            # Adversarial witnesses bypass the host relation entirely.
            bad_parent = bytearray(token_parent.serialize()); bad_parent[5] ^= 1
            self.assertIn("Assert Failed", witness(statement, expected, parent=list(bad_parent)).stderr)
            bad_outputs = bytearray(bound.outputs); bad_outputs[20] ^= 1
            self.assertIn("Assert Failed", witness(statement, expected, outputs=list(bad_outputs)).stderr)
            # Conserving claims with both sides inflated must fail against real amounts.
            claimed = transfer_bytes(fixture.asset, verifier_key_id(prover.key), tx, parent, lock,
                                     (replace(fixture.inputs[0], quantity=1025),),
                                     (fixture.outputs[0], replace(fixture.outputs[1], quantity=385)),
                                     script_code=COMPACT_SCRIPTCODE)
            self.assertIn("Assert Failed", witness(claimed, public_inputs(claimed)).stderr)
            # Recompute every hash and public input for a successor with a different guard.
            wrong_lock = token_lock(replace(state, quantity=640), lock + b"\x51")
            wrong_tx = replace(tx, outputs=(Output(1, wrong_lock), tx.outputs[1]))
            wrong_statement = transfer_bytes(fixture.asset, verifier_key_id(prover.key), wrong_tx, parent,
                                            lock, fixture.inputs, fixture.outputs, script_code=COMPACT_SCRIPTCODE)
            self.assertIn("Assert Failed", witness(
                wrong_statement, public_inputs(wrong_statement),
                preimage_all(wrong_tx, 0, verifier_value, COMPACT_SCRIPTCODE),
                outputs=list(b"".join(o.serialize() for o in wrong_tx.outputs))).stderr)

            script_sig = verifier_witness(
                fixture.asset, prover.key, proof, tx, parent, fixture.inputs, fixture.outputs,
            )

            def native_signature(actual_tx):
                digest = hash256(preimage_all(actual_tx, 0, verifier_value, COMPACT_SCRIPTCODE))

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

                token_preimage = preimage_all(tx, 1, carrier, token_parent.outputs[0].script)
                token_witness = (push(authorization(signer, token_preimage)) + push(parent.serialize())
                                 + push(bound.prevouts) + push(token_preimage))
                signed = tx.with_script(0, script_sig).with_script(1, token_witness)
                validate_at_heights(signed, (parent, token_parent),
                                    spend_height=100, activation_height=2, utxo_heights=(3, 3))
                if node:
                    from regtest_mint import RpcFailure
                    # Keep parents unspent while checking the invalid transaction.
                    bad = replace(signed, outputs=signed.outputs[::-1])
                    with self.assertRaises(RpcFailure) as rejected:
                        node.submit(bad)
                    node.confirm(signed, address)
                    if os.environ.get("CCTP_REPORT"):
                        from circom_fixture_prover import export_artifacts
                        vk, proof_json, public_json = export_artifacts(prover.key, signals, proof)
                        report = {
                            "scope": "actual split relation; synthetic origin; no recursive provenance",
                            "node": node.call("getnetworkinfo")["subversion"],
                            "constraints": len(prover.rows), "transaction_bytes": len(signed.serialize()),
                            "parent_txid": token_parent.txid(), "split_txid": signed.txid(),
                            "blockhash": node.call("getrawtransaction", signed.txid(), True)["blockhash"],
                            "reordered_outputs_rejection": str(rejected.exception),
                            "transaction_hex": signed.serialize().hex(),
                            "parents_hex": [parent.serialize().hex(), token_parent.serialize().hex()],
                            "verification_key": vk, "proof": proof_json, "public_inputs": public_json,
                        }
                        Path(os.environ["CCTP_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")

from dataclasses import replace
from hashlib import new, sha256
from importlib.util import find_spec
import json
import os
from pathlib import Path
import unittest

from ecdsa import SECP256k1, SigningKey
from fixtures import G1
from regtest_mint import Node, RpcFailure, base58check, sign_p2pkh
from shared.evaluate import evaluate, ScriptError
from shared.script import push
from shared.transaction import Input, Output, Transaction, hash256
from verifier import Curve, Host, unlocking_script

from committed_verifier import (load_artifact, recursive_digest_script, standalone_witness,
                                verifier_fields, verifier_lock)


class CommittedVerifierTests(unittest.TestCase):
    def test_bsb22_proof_and_public_commitment(self):
        path = Path(os.environ.get("CCTP_BSB22_ARTIFACT", Path(__file__).parent / "testdata/bsb22-proof.json"))
        key, relation, signals, proof = load_artifact(json.loads(path.read_text()))
        lock = verifier_lock(key, relation)
        if os.environ.get("CCTP_BSB22_INPUT"):
            fixture = json.loads(Path(os.environ["CCTP_BSB22_INPUT"]).read_text())
            digests = [hash256(bytes.fromhex(parent["statement"])) for parent in fixture["parents"]]
            digests.append(bytes.fromhex(fixture["context"]))
        elif "CCTP_BSB22_ARTIFACT" not in os.environ:
            digests = [hash256(value) for value in (b"parent 0", b"parent 1", b"current")]
        else:
            digests = []
        if digests:
            lock = recursive_digest_script() + lock

        def witness(public, committed):
            if not digests:
                return standalone_witness(key, relation, public, committed)
            return (unlocking_script(verifier_fields(key, relation, public, committed))
                    + b"".join(push(digest) for digest in digests))

        valid = witness(signals, proof)
        self.assertEqual(evaluate(valid + lock), ([b'\x01'], []))
        # Rebuild the entire witness for each changed input, including residue
        # hints. The verifier must check the pairing equations themselves.
        wrong_signals = signals[0] ^ 1, signals[1]
        wrong_pok = replace(proof, knowledge_proof=Curve(Host()).add_host(proof.knowledge_proof, G1))
        for label, wrong in (
            ("public signals", witness(wrong_signals, proof)),
            ("knowledge proof", witness(signals, wrong_pok)),
        ):
            with self.subTest(changed=label), self.assertRaises(ScriptError):
                evaluate(wrong + lock)
        if find_spec("tx_engine") is not None:
            from shared.chain_gang import validate_at_heights

            parent = Transaction((Input(hash256(b"gnark BSB22 verifier test parent"), 0),), (Output(2, lock),))
            spend = Transaction((Input(parent.txid_wire(), 0, valid),), (Output(1, b'\x51'),))
            validate_at_heights(spend, (parent,), spend_height=100, activation_height=2, utxo_heights=(3,))
        if os.environ.get("REGTEST_COOKIE"):
            node = Node(os.environ["REGTEST_URL"], Path(os.environ["REGTEST_COOKIE"]))
            signer = SigningKey.from_secret_exponent(13, curve=SECP256k1)  # Test-only.
            public_key = signer.verifying_key.to_string("compressed")
            address = base58check(b"\x6f" + new("ripemd160", sha256(public_key).digest()).digest())
            coinbase = node.fund(address)
            parent = Transaction((Input(coinbase.txid_wire(), 0),), (Output(100_000_000, lock),))
            parent = sign_p2pkh(parent, coinbase, 0, signer)
            node.confirm(parent, address)
            spend = Transaction((Input(parent.txid_wire(), 0, valid),), (Output(90_000_000, b'\x51'),))
            invalid = spend.with_script(0, witness(signals, wrong_pok))
            with self.assertRaises(RpcFailure) as failure:
                node.submit(invalid)
            self.assertIn("mandatory-script-verify-flag-failed", str(failure.exception))
            node.confirm(spend, address)

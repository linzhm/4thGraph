"""Explicit CPN declaration over the fixed-parent CCTP 2-to-2 fixture."""

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import unittest

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize

from fourthgraph.benchmark.validation import Node, chain_verdict
from fourthgraph.bsv.script import push, script_operations
from fourthgraph.bsv.transaction import hash256, preimage_all
from fourthgraph.workflow.cctp_archive import OWNER_OFFSET, QUANTITY_OFFSET
from fourthgraph.workflow.cctp_declared_fixture import construct_declared_fixture_spend, fixture_declaration
from fourthgraph.workflow.cctp_transfer_fixture import COMPACT_SCRIPTCODE
from fourthgraph.workflow.logical_cpn import validate_document

ARCHIVE = os.environ.get("CCTP_ARCHIVE")


@unittest.skipUnless(ARCHIVE, "set CCTP_ARCHIVE to the pinned public CCTP fixture")
class DeclaredFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = Path(ARCHIVE)
        cls.model = fixture_declaration(cls.archive)
        cls.key = SigningKey.from_secret_exponent(21, curve=SECP256k1)
        cls.owner = cls.key.verifying_key.to_string("compressed")
        cls.bob = SigningKey.from_secret_exponent(22, curve=SECP256k1).verifying_key.to_string("compressed")

    @classmethod
    def signer(cls, vin, digest, owner):
        if vin not in (1, 2) or owner != cls.owner:
            raise ValueError("unexpected fixture signer")
        for attempt in range(256):
            der = cls.key.sign_digest_deterministic(
                digest, hashfunc=sha256, sigencode=sigencode_der_canonize, extra_entropy=bytes([attempt]))
            if len(der) == 70:
                return der
        raise ValueError("could not produce the required 70-byte DER signature")

    def spend(self, model=None):
        return construct_declared_fixture_spend(
            self.archive, self.model if model is None else model, ((276, self.bob), (224, self.owner)), self.signer)

    def test_symbolic_output_places_get_actual_outpoints_and_state(self):
        model = deepcopy(self.model)
        model["transitions"][0]["name"] = "pay"
        rename = {"funding": "proof-fee", "token-a": "first-input", "token-b": "second-input",
                  "output-a": "recipient", "output-b": "change"}
        for place in model["places"]:
            place["name"] = rename[place["name"]]
        for arc in model["transitions"][0]["inputs"] + model["transitions"][0]["outputs"]:
            arc["place"] = rename[arc["place"]]
        result = self.spend(model)
        self.assertTrue(validate_document(result.cpn)["ok"])
        self.assertEqual(result.cpn["transitions"][0]["name"], "pay")
        outputs = result.cpn["places"][-2:]
        self.assertEqual([row["name"] for row in outputs], ["recipient", "change"])
        self.assertEqual([row["metadata"]["token"]["quantity"] for row in outputs], [276, 224])
        self.assertEqual([row["metadata"]["actual_outpoint"] for row in outputs],
                         [result.transaction.txid() + ":0", result.transaction.txid() + ":1"])
        self.assertIn("chain admission not established", result.cpn["transitions"][0]["metadata"]["status"])

    def test_unmatched_requirements_fail_before_signing(self):
        def forbidden_signer(*args):
            raise AssertionError("signing happened before the requirement check")
        tests = []
        doc = deepcopy(self.model)
        doc["transitions"][0]["metadata"]["evidence"][0]["proof_sha256"] = "00" * 32
        tests.append(doc)
        doc = deepcopy(self.model)
        doc["transitions"][0]["metadata"]["authorization"][0]["owner_compressed"] = self.bob.hex()
        tests.append(doc)
        doc = deepcopy(self.model)
        doc["transitions"][0]["metadata"]["constraints"].append({"kind": "other"})
        tests.append(doc)
        doc = deepcopy(self.model)
        doc["transitions"][0]["metadata"]["witnesses"].pop()
        tests.append(doc)
        doc = deepcopy(self.model)
        doc["places"][1]["metadata"]["actual_outpoint"] = "00" * 32 + ":0"
        tests.append(doc)
        doc = deepcopy(self.model)
        doc["places"][0]["metadata"]["script_sha256"] = "00" * 32
        tests.append(doc)
        doc = deepcopy(self.model)
        doc["places"][3]["metadata"]["minimum"] = 1
        tests.append(doc)
        doc = deepcopy(self.model)
        doc["transitions"][0]["inputs"][1], doc["transitions"][0]["inputs"][2] = (
            doc["transitions"][0]["inputs"][2], doc["transitions"][0]["inputs"][1])
        tests.append(doc)
        for doc in tests:
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                construct_declared_fixture_spend(self.archive, doc, ((276, self.bob), (224, self.owner)), forbidden_signer)

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires loopback BSV regtest RPC")
    def test_real_engines_accept_and_reject_resigned_inflation(self):
        result = self.spend()
        tx, parents = result.transaction, result.parents
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        self.assertEqual(node.verdicts(tx, parents, timeout_us=2_000_000), [True, True, True])
        self.assertTrue(chain_verdict(tx, parents))

        old = tx.outputs[0]
        raw = old.script
        inflated = replace(old, script=raw[:QUANTITY_OFFSET] + (277).to_bytes(8, "little") + raw[QUANTITY_OFFSET + 8:])
        bad = replace(tx, outputs=(inflated, tx.outputs[1]))
        operations = list(script_operations(tx.inputs[0].script))
        prevouts = b"".join(item.outpoint() for item in bad.inputs)
        output_states = b"".join(output.script[QUANTITY_OFFSET:QUANTITY_OFFSET + 8]
                                 + output.script[OWNER_OFFSET:OWNER_OFFSET + 33] for output in bad.outputs)
        preimage = preimage_all(bad, 0, parents[0].outputs[bad.inputs[0].vout].value, COMPACT_SCRIPTCODE)
        bad = bad.with_script(0, b"".join(operations[:22]) + push(output_states) + operations[-3]
                              + push(prevouts) + push(preimage))
        for vin in (1, 2):
            previous = parents[vin].outputs[bad.inputs[vin].vout]
            digest = hash256(preimage_all(bad, vin, previous.value, previous.script))
            signature = self.signer(vin, digest, self.owner)
            preimage = preimage_all(bad, vin, previous.value, COMPACT_SCRIPTCODE)
            bad = bad.with_script(vin, push(signature + b"\x41") + push(prevouts) + push(preimage))
        self.assertEqual(node.verdicts(bad, parents, timeout_us=2_000_000), [False, True, True])
        self.assertFalse(chain_verdict(bad, parents))


if __name__ == "__main__":
    unittest.main()

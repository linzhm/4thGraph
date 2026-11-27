"""Tests of the pinned CCTP parent-opening adapter with public fixture keys."""

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
from fourthgraph.workflow.cctp_archive import OWNER_OFFSET, QUANTITY_OFFSET, inspect_archive, logical_model, read_archive
from fourthgraph.workflow.cctp_transfer_fixture import COMPACT_SCRIPTCODE, construct_fixture_spend

ARCHIVE = os.environ.get("CCTP_ARCHIVE")


@unittest.skipUnless(ARCHIVE, "set CCTP_ARCHIVE to the pinned public CCTP fixture")
class FixedFixtureSpendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = Path(ARCHIVE)
        data, digest = read_archive(cls.archive)
        cls.model = logical_model(inspect_archive(data, archive_sha256=digest))
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

    def spend(self):
        return construct_fixture_spend(self.archive, self.model, ((276, self.bob), (224, self.owner)), self.signer)

    def test_constructs_exact_parent_ports_with_external_signer(self):
        result = self.spend()
        tx = result.transaction
        self.assertEqual(len(tx.serialize()), 4075)
        transition, = result.cpn["transitions"]
        self.assertEqual([arc["place"] for arc in transition["inputs"]],
                         [f"{vin.txid[::-1].hex()}:{vin.vout}" for vin in tx.inputs])
        self.assertEqual([arc["place"] for arc in transition["outputs"]],
                         [f"{tx.txid()}:0", f"{tx.txid()}:1"])
        self.assertEqual([place["metadata"]["token"]["quantity"] for place in result.cpn["places"][-2:]],
                         [276, 224])
        self.assertEqual(transition["metadata"]["status"], "constructed; chain admission not established")

    def test_rejects_unbalanced_or_invalid_signer_and_changed_model(self):
        with self.assertRaisesRegex(ValueError, "do not balance"):
            construct_fixture_spend(self.archive, self.model, ((277, self.bob), (224, self.owner)), self.signer)
        other = SigningKey.from_secret_exponent(22, curve=SECP256k1)

        def wrong(vin, digest, owner):
            for attempt in range(256):
                der = other.sign_digest_deterministic(
                    digest, hashfunc=sha256, sigencode=sigencode_der_canonize, extra_entropy=bytes([attempt]))
                if len(der) == 70:
                    return der
            raise AssertionError("could not find test signature")

        with self.assertRaisesRegex(ValueError, "invalid owner signature"):
            construct_fixture_spend(self.archive, self.model, ((276, self.bob), (224, self.owner)), wrong)
        model = {**self.model, "transitions": self.model["transitions"][:-1]}
        with self.assertRaisesRegex(ValueError, "logical CPN differs"):
            construct_fixture_spend(self.archive, model, ((276, self.bob), (224, self.owner)), self.signer)

    @unittest.skipUnless(os.environ.get("REGTEST_URL"), "requires loopback BSV regtest RPC")
    def test_both_engines_accept_and_reject_resigned_inflation(self):
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

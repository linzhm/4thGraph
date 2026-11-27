"""Exercise byte-based extraction of archived CCTP state and transaction slots."""

from dataclasses import replace
from hashlib import sha256
import unittest

from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.workflow.cctp_archive import OWNER_PREFIX, TOKEN_PREFIX, inspect_archive, logical_model
from fourthgraph.workflow.logical_cpn import analyze, parse_net, validate_document


def fixture():
    def tx(inputs, outputs):
        return Transaction(tuple(inputs), tuple(outputs), version=1)

    root = tx((Input(bytes(32), 0),), (Output(1, b"1"), Output(2, b"2"), Output(3, b"3")))
    funding = tx((Input(bytes([1]) * 32, 0),), (Output(8, b"guard"), Output(8, b"guard")))
    owner = b"\x02" + bytes([7]) * 32

    def token(quantity):
        return Output(1000, TOKEN_PREFIX + quantity.to_bytes(8, "little") + OWNER_PREFIX
                      + owner + b"fixed-prefix" + funding.txid_wire() + b"fixed-suffix")

    mints = [tx((Input(root.txid_wire(), index),), (token(quantity),))
             for index, quantity in enumerate((300, 200, 150))]
    first = tx((Input(funding.txid_wire(), 0), Input(mints[0].txid_wire(), 0), Input(mints[1].txid_wire(), 0)),
               (token(275), token(225)))
    second = tx((Input(funding.txid_wire(), 1), Input(first.txid_wire(), 0), Input(mints[2].txid_wire(), 0)),
                (token(350), token(75)))
    named = dict(zip(("issuance-root", "verifier-funding", "alice-mint-1", "alice-mint-2", "bob-mint",
                      "alice-to-bob", "bob-to-carol"), (root, funding, *mints, first, second), strict=True))
    records = {name: {"txid": item.txid(), "bytes": len(item.serialize())} for name, item in named.items()}
    payments = {name: {"direct_token_parents": [f"{item.txid[::-1].hex()}:{item.vout}" for item in named[name].inputs[1:]]}
                for name in ("alice-to-bob", "bob-to-carol")}
    return {"recipient_policy": {"issuance_root": root.txid(), "verifier_funding": funding.txid(),
                                  "verifier_lock_sha256": sha256(b"guard").hexdigest(),
                                  "verifying_key_sha256": "fixture"},
            "summary": {"transactions": records, "payments": payments},
            "transactions": {item.txid(): item.serialize().hex() for item in named.values()}}


class ArchiveGraphTests(unittest.TestCase):
    def test_graph_preserves_intermediate_token_and_distinguishes_satoshis(self):
        archive = fixture()
        graph = inspect_archive(archive)
        first, second = graph["transitions"][-2:]
        self.assertEqual(first["outputs"][0], second["inputs"][1])
        places = {place["id"]: place for place in graph["places"]}
        self.assertEqual(places[first["outputs"][0]]["satoshis"], 1000)
        self.assertEqual(places[first["outputs"][0]]["token"]["quantity"], 275)
        self.assertEqual(places[first["inputs"][0]]["kind"], "verifier-funding")
        self.assertEqual(graph["validation"]["script_execution"], "not checked")
        self.assertEqual(len([edge for edge in graph["edges"] if edge["to"] == second["id"]]), 3)

    def test_archive_hash_and_external_policy_are_checked(self):
        archive = fixture()
        txid = archive["summary"]["transactions"]["alice-to-bob"]["txid"]
        archive["transactions"][txid] = archive["transactions"][txid][:-2] + "01"
        with self.assertRaisesRegex(ValueError, "transaction does not match"):
            inspect_archive(archive)
        archive = fixture()
        with self.assertRaisesRegex(ValueError, "supplied policy"):
            inspect_archive(archive, policy={"issuance_root": "unrelated"})

    def test_logical_graph_connects_actual_outpoints_and_boundary_marking(self):
        graph = inspect_archive(fixture())
        document = logical_model(graph)
        self.assertTrue(validate_document(document)["ok"])
        self.assertEqual(len(document["places"]), len(graph["places"]))
        self.assertEqual(len(document["transitions"]), 5)
        by_name = {place["name"]: place for place in document["places"]}
        first, second = document["transitions"][-2:]
        handed_over = first["outputs"][0]["place"]
        self.assertEqual(handed_over, second["inputs"][1]["place"])
        self.assertEqual(by_name[handed_over]["metadata"]["token"]["quantity"], 275)
        self.assertEqual(by_name[handed_over]["initial"], 0)
        self.assertEqual(by_name[first["inputs"][0]["place"]]["initial"], 1)
        self.assertEqual(by_name[handed_over]["metadata"]["archive_validation"]["script_execution"], "not checked")
        self.assertEqual(analyze(parse_net(document))["never_enabled"], [])

    def test_forged_vout_is_rejected_after_rehash(self):
        archive = fixture()
        record = archive["summary"]["transactions"]["alice-to-bob"]
        original = Transaction.parse(bytes.fromhex(archive["transactions"][record["txid"]]))
        bad_input = replace(original.inputs[1], vout=9)
        bad = replace(original, inputs=(original.inputs[0], bad_input, original.inputs[2]))
        record.update(txid=bad.txid(), bytes=len(bad.serialize()))
        archive["transactions"][bad.txid()] = bad.serialize().hex()
        with self.assertRaisesRegex(ValueError, "no matching archived parent"):
            inspect_archive(archive)

    def test_unapproved_root_is_rejected_after_rehash(self):
        archive = fixture()
        record = archive["summary"]["transactions"]["alice-mint-1"]
        original = Transaction.parse(bytes.fromhex(archive["transactions"][record["txid"]]))
        bad = replace(original, inputs=(replace(original.inputs[0], vout=1),))
        record.update(txid=bad.txid(), bytes=len(bad.serialize()))
        archive["transactions"][bad.txid()] = bad.serialize().hex()
        with self.assertRaisesRegex(ValueError, "issuance anchor slot"):
            inspect_archive(archive)


if __name__ == "__main__":
    unittest.main()

"""Exercise byte-based extraction of archived CCTP state and transaction slots."""

from dataclasses import replace
from hashlib import sha256
import unittest

from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.workflow.cctp_archive import OWNER_PREFIX, TOKEN_PREFIX, flow_report, inspect_archive, logical_model
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
    @staticmethod
    def rewrite_second_payment(archive, parent, vout, output_slot, quantity):
        record = archive["summary"]["transactions"]["bob-to-carol"]
        tx = Transaction.parse(bytes.fromhex(archive["transactions"][record["txid"]]))
        token_input = replace(tx.inputs[2], txid=bytes.fromhex(parent)[::-1], vout=vout)
        output = tx.outputs[output_slot]
        pos = len(TOKEN_PREFIX)
        script = output.script[:pos] + quantity.to_bytes(8, "little") + output.script[pos + 8:]
        outputs = list(tx.outputs)
        outputs[output_slot] = replace(output, script=script)
        changed = replace(tx, inputs=(*tx.inputs[:2], token_input), outputs=tuple(outputs))
        record.update(txid=changed.txid(), bytes=len(changed.serialize()))
        archive["transactions"][changed.txid()] = changed.serialize().hex()
        archive["summary"]["payments"]["bob-to-carol"]["direct_token_parents"] = [
            f"{item.txid[::-1].hex()}:{item.vout}" for item in changed.inputs[1:]]

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

    def test_bounded_flow_tracks_amount_owner_ports_and_real_handoff(self):
        report = flow_report(fixture())
        first, second = report["steps"][-2:]
        self.assertEqual([item["port"] for item in first["inputs"]], ["vin:0", "vin:1", "vin:2"])
        self.assertEqual([item["port"] for item in first["outputs"]], ["vout:0", "vout:1"])
        self.assertEqual([item["quantity"] for item in first["inputs"][1:]], [300, 200])
        self.assertEqual([item["quantity"] for item in first["outputs"]], [275, 225])
        self.assertEqual([item["quantity"] for item in second["inputs"][1:]], [275, 150])
        self.assertEqual([item["quantity"] for item in second["outputs"]], [350, 75])
        self.assertEqual(first["outputs"][0]["outpoint"], second["inputs"][1]["outpoint"])
        self.assertEqual(first["outputs"][0]["owner_compressed"], second["inputs"][1]["owner_compressed"])
        self.assertEqual(first["outputs"][0]["satoshis"], 1000)
        self.assertEqual(report["invariants"]["issued_token_quantity"], 650)
        self.assertEqual(report["invariants"]["remaining_token_quantity"], 650)
        self.assertIn({"outpoint": first["outputs"][0]["outpoint"], "from": first["name"], "to": second["name"],
                       "input_port": "vin:1", "quantity": 275,
                       "owner_compressed": first["outputs"][0]["owner_compressed"]}, report["handoffs"])
        self.assertEqual(report["validation"]["transaction_signatures"], "not checked")
        self.assertEqual(report["validation"]["script_execution"], "not checked")

    def test_archive_rejects_token_outpoint_consumed_by_two_transfers(self):
        archive = fixture()
        # The first transfer already consumed this 300-unit mint.  Keep the
        # second transfer balanced and update its txid and reported parents so
        # only the cross-transaction double spend distinguishes the archive.
        parent = archive["summary"]["transactions"]["alice-mint-1"]["txid"]
        self.rewrite_second_payment(archive, parent, 0, 0, 500)
        for inspect in (inspect_archive, flow_report):
            with self.subTest(inspector=inspect.__name__), self.assertRaisesRegex(ValueError, "already consumed"):
                inspect(archive)

    def test_archive_allows_distinct_outputs_of_the_same_parent(self):
        archive = fixture()
        parent = archive["summary"]["transactions"]["alice-to-bob"]["txid"]
        # Both inputs now come from the first transfer, but the vouts differ:
        # 275 + 225 = 350 + 150.  Bob's mint remains unspent in this subgraph.
        self.rewrite_second_payment(archive, parent, 1, 1, 150)
        graph = inspect_archive(archive)
        self.assertEqual(graph["transitions"][-1]["inputs"][1:], [parent + ":0", parent + ":1"])
        self.assertEqual(graph["validation"]["unique_input_consumption"],
                         "checked within selected archive only")
        self.assertEqual(flow_report(archive)["invariants"]["remaining_token_quantity"], 650)

    def test_bounded_flow_rejects_inflation_after_transaction_rehash(self):
        archive = fixture()
        record = archive["summary"]["transactions"]["alice-to-bob"]
        original = Transaction.parse(bytes.fromhex(archive["transactions"][record["txid"]]))
        output = original.outputs[0]
        pos = len(TOKEN_PREFIX)
        changed = output.script[:pos] + (276).to_bytes(8, "little") + output.script[pos + 8:]
        bad = replace(original, outputs=(replace(output, script=changed), original.outputs[1]))
        record.update(txid=bad.txid(), bytes=len(bad.serialize()))
        archive["transactions"][bad.txid()] = bad.serialize().hex()
        with self.assertRaisesRegex(ValueError, "token quantities do not balance"):
            flow_report(archive)

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

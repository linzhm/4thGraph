"""Offline replay of actual BSV Node Chronicle boundary receipts."""

import gzip
from importlib.util import find_spec
import json
from pathlib import Path
import unittest

from run_chronicle_regtest import PROFILES, SKIPPED_CLEAN, SKIPPED_SEPARATOR, DualBinding, _mining_key, boundary_cases, raw_block
from shared.transaction import Transaction, hash256


class ChronicleRegtestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "fixtures/chronicle-activation-regtest.json.gz"
        with gzip.open(path, "rt") as stream:
            cls.archive = json.load(stream)
        cls.funding = {era: Transaction.parse(bytes.fromhex(row["raw"]))
                       for era, row in cls.archive["funding"].items()}
        cls.cases = {row["case"]: (row, Transaction.parse(bytes.fromhex(row["raw"])))
                     for row in cls.archive["cases"]}

    def test_script_code_keeps_data_and_distinguishes_executed_separators(self):
        mixed = DualBinding(0x41, 0x61)
        reverse = DualBinding(0x61, 0x41)
        self.assertTrue(mixed.script_code(0).startswith(SKIPPED_SEPARATOR))
        self.assertTrue(mixed.script_code(1).startswith(SKIPPED_CLEAN))
        self.assertTrue(reverse.script_code(0).startswith(SKIPPED_CLEAN))
        self.assertTrue(reverse.script_code(1).startswith(SKIPPED_SEPARATOR))
        self.assertIn(b"\x02\xab\x55", mixed.script_code(1))
        self.assertIn(b"\x02\xab\x55", reverse.script_code(0))
        self.assertNotEqual(reverse.script_code(0), reverse.script_code(0, wrong_separator=True))
        self.assertNotEqual(mixed.script_code(0), mixed.script_code(0, wrong_separator=True))

    def assert_block(self, receipt, transactions):
        header = bytes.fromhex(receipt["header"])
        timestamp = int.from_bytes(header[68:72], "little")
        previous = {"height": receipt["height"] - 1, "hash": receipt["previous"], "time": timestamp - 1,
                    "mediantime": timestamp - 1, "bits": header[72:76][::-1].hex()}
        _, lock, _ = _mining_key()
        block_hash, raw = raw_block(previous, transactions, lock)
        self.assertEqual(raw[:80], header)
        self.assertEqual(hash256(header)[::-1].hex(), block_hash)
        self.assertEqual(block_hash, receipt["hash"])

    def test_archive_covers_actual_outpoints_and_reconstructs_submitted_block_headers(self):
        declared = boundary_cases()
        self.assertEqual(list(self.cases), [case.name for case in declared])
        activation = self.archive["activation_height"]
        heights = {era: self.archive["funding"][era]["height"] for era in self.funding}
        self.assertEqual(heights, {"old": activation - 2, "new": activation})
        self.assert_block(self.archive["funding"]["old"]["block"], (self.funding["old"],))
        for case in declared:
            row, tx = self.cases[case.name]
            with self.subTest(case=case.name):
                self.assertEqual(tx.txid(), row["txid"])
                self.assertEqual(tx.version, row["version"])
                self.assertEqual(row["height"], activation + case.height_delta)
                self.assertEqual(row["created_heights"], [heights[era] for era in case.eras])
                self.assertEqual([vin.txid for vin in tx.inputs], [self.funding[era].txid_wire() for era in case.eras])
                for vin, era, flags in zip(tx.inputs, case.eras, PROFILES[case.profile], strict=True):
                    self.assertEqual(self.funding[era].outputs[vin.vout].script, DualBinding(*flags).lock)
                self.assertEqual(row["admission"]["accepted"], case.consensus)
                self.assertEqual(row["block"]["accepted"], case.consensus)
                if not case.consensus:
                    same_block_funding = (self.funding["new"],) if case.height_delta == 0 else ()
                    self.assert_block(row["block"], (*same_block_funding, tx))
        for block in self.archive["mined_blocks"]:
            same_block_funding = (self.funding["new"],) if block["height"] == activation else ()
            paid = tuple(tx for row, tx in self.cases.values() if row["block"]["hash"] == block["hash"])
            self.assert_block(block, (*same_block_funding, *paid))

    @unittest.skipUnless(find_spec("tx_engine"), "requires pinned chain-gang")
    def test_chain_gang_matches_all_node_consensus_receipts(self):
        from shared.chain_gang import validate_at_heights

        for case in boundary_cases():
            row, tx = self.cases[case.name]
            parents = tuple(self.funding[era] for era in case.eras)
            context = {"spend_height": row["height"], "activation_height": self.archive["activation_height"],
                       "utxo_heights": row["created_heights"]}
            with self.subTest(case=case.name):
                if row["block"]["accepted"]:
                    validate_at_heights(tx, parents, **context)
                else:
                    with self.assertRaisesRegex((ValueError, RuntimeError), "Error evaluating the script"):
                        validate_at_heights(tx, parents, **context)


if __name__ == "__main__":
    unittest.main()

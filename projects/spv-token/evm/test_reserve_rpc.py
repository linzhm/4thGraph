from dataclasses import replace
import unittest

from mint_events import DepositPosition
from evm.mint_adapter import finalized_deposit_reader
from evm.reserve_rpc import (
    DEPOSIT_TOPIC, DepositEvidenceError, ReserveScope, read_finalized_deposit,
)


def hx(value):
    return "0x" + value.hex()


def word(value):
    return value.to_bytes(32, "big")


class ReserveRpcTests(unittest.TestCase):
    def setUp(self):
        self.scope = ReserveScope(84532, 7, 1, b"v" * 20, b"s" * 20, b"a" * 32)
        self.tx_hash = b"t" * 32
        self.hash = b"b" * 32
        self.owner = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        self.depositor = b"d" * 20
        self.log = {
            "logIndex": "0xc",
            "removed": False,
            "blockHash": hx(self.hash),
            "blockNumber": "0xa",
            "transactionHash": hx(self.tx_hash),
            "transactionIndex": "0x1",
            "address": hx(self.scope.vault),
            "topics": [hx(DEPOSIT_TOPIC), hx(word(1)), hx(bytes(12) + self.depositor), hx(self.scope.asset_id)],
            "data": hx(
                word(self.scope.reserve_domain) + word(self.scope.bsv_network)
                + bytes(12) + self.scope.reserve_asset + word(1024) + word(160) + word(33)
                + self.owner + bytes(31)
            ),
        }
        # An ERC-20 Transfer from the same receipt precedes the reserve log.
        transfer = dict(self.log, logIndex="0xb", address=hx(self.scope.reserve_asset), topics=[])
        self.receipt = {
            "status": "0x1", "transactionHash": hx(self.tx_hash),
            "blockHash": hx(self.hash), "blockNumber": "0xa", "transactionIndex": "0x1",
            "logs": [transfer, self.log],
        }
        self.finalized = {"number": "0xf", "hash": hx(b"f" * 32)}
        self.canonical = {"number": "0xa", "hash": hx(self.hash), "transactions": [hx(b"x" * 32), hx(self.tx_hash)]}
        self.rpc_values = {
            ("eth_chainId",): hex(self.scope.chain_id),
            ("eth_getTransactionReceipt", hx(self.tx_hash)): self.receipt,
            ("eth_getBlockByNumber", "finalized", False): self.finalized,
            ("eth_getBlockByNumber", "0xa", False): self.canonical,
        }

    def rpc(self, *args):
        return self.rpc_values[args]

    def read(self, ordinal=1):
        return read_finalized_deposit(self.rpc, self.scope, self.tx_hash, ordinal)

    def test_finalized_receipt_maps_to_canonical_mint_payload(self):
        evidence = self.read()
        self.assertEqual(evidence.receipt_log_ordinal, 1)
        self.assertEqual(evidence.owner, self.owner)
        self.assertEqual(evidence.depositor, self.depositor)
        self.assertEqual(evidence.vault_nonce, 1)
        self.assertEqual(evidence.quantity, 1024)
        self.assertEqual((evidence.block_number, evidence.finalized_number), (10, 15))
        self.assertEqual(evidence.block_hash, self.hash)

        observer = finalized_deposit_reader(self.rpc, self.scope)
        position = DepositPosition(self.scope.chain_id, self.scope.reserve_domain, self.scope.vault, self.tx_hash, 1)
        deposit = observer(position)
        self.assertEqual(deposit.position, position)
        self.assertEqual(deposit.destination_network, self.scope.bsv_network)
        self.assertEqual(deposit.asset_id, self.scope.asset_id)
        self.assertEqual(deposit.reserve_asset, bytes(12) + self.scope.reserve_asset)
        self.assertEqual(deposit.owner, self.owner)
        self.assertEqual(deposit.net_quantity, 1024)
        self.assertEqual(len(deposit.encode()), 185)
        self.assertIsNone(observer(replace(position, reserve_contract=bytes(20))))
        self.assertIsNone(observer(replace(position, source_chain_id=1)))

    def test_rejects_nonfinal_and_replaced_block(self):
        self.finalized["number"] = "0x9"
        with self.assertRaisesRegex(DepositEvidenceError, "not finalized"):
            self.read()
        self.finalized["number"] = "0xa"
        with self.assertRaisesRegex(DepositEvidenceError, "not canonical"):
            self.read()
        self.finalized["number"] = "0xf"
        self.canonical["hash"] = hx(b"r" * 32)
        with self.assertRaisesRegex(DepositEvidenceError, "not canonical"):
            self.read()

    def test_rejects_wrong_chain_and_missing_finality(self):
        self.rpc_values[("eth_chainId",)] = "0x1"
        with self.assertRaisesRegex(DepositEvidenceError, "does not match reserve"):
            self.read()
        self.rpc_values[("eth_chainId",)] = hex(self.scope.chain_id)
        self.rpc_values[("eth_getBlockByNumber", "finalized", False)] = None
        with self.assertRaisesRegex(DepositEvidenceError, "malformed finalized block"):
            self.read()

    def test_rejects_reverted_missing_or_wrong_tx_position(self):
        self.receipt["status"] = "0x0"
        with self.assertRaisesRegex(DepositEvidenceError, "did not succeed"):
            self.read()
        self.receipt["status"] = "0x1"
        self.canonical["transactions"] = [hx(self.tx_hash), hx(b"x" * 32)]
        with self.assertRaisesRegex(DepositEvidenceError, "canonical position"):
            self.read()
        self.rpc_values[("eth_getTransactionReceipt", hx(self.tx_hash))] = None
        with self.assertRaisesRegex(DepositEvidenceError, "malformed transaction receipt"):
            self.read()

    def test_rejects_wrong_emitter_removed_or_receipt_ordinal(self):
        with self.assertRaisesRegex(DepositEvidenceError, "missing receipt-local"):
            self.read(12)
        with self.assertRaisesRegex(DepositEvidenceError, "log emitter"):
            self.read(0)
        self.log["removed"] = True
        with self.assertRaisesRegex(DepositEvidenceError, "canonical receipt position"):
            self.read()
        self.log["removed"] = False
        self.log["address"] = hx(b"x" * 20)
        with self.assertRaisesRegex(DepositEvidenceError, "log emitter"):
            self.read()

    def test_rejects_wrong_event_asset_and_noncanonical_owner_data(self):
        original_topics = self.log["topics"].copy()
        self.log["topics"][3] = hx(b"x" * 32)
        with self.assertRaisesRegex(DepositEvidenceError, "bridge asset"):
            self.read()
        self.log["topics"] = original_topics
        data = bytes.fromhex(self.log["data"][2:])
        self.log["data"] = hx(word(8) + data[32:])
        with self.assertRaisesRegex(DepositEvidenceError, "domain, BSV network, or reserve asset mismatch"):
            self.read()
        self.log["data"] = hx(data[:-1] + b"\x01")
        with self.assertRaisesRegex(DepositEvidenceError, "invalid compressed deposit owner"):
            self.read()


if __name__ == "__main__":
    unittest.main()

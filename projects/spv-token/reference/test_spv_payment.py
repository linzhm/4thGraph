import unittest
from dataclasses import replace
from itertools import count

from shared.transaction import Input, Output, Transaction, hash256
from spv_payment import REGTEST_BITS, REGTEST_TARGET, RegtestHeaderChain, TxInclusion, verify_receipt
from wallet_receipt import BlockInclusion, SpendStatus


GENESIS = bytes.fromhex(
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "dae5494dffff7f2002000000"
)


def child_header(previous, merkle):
    timestamp = int.from_bytes(previous[68:72], "little") + 1
    prefix = b"\x01\0\0\0" + hash256(previous) + merkle + timestamp.to_bytes(4, "little") + REGTEST_BITS
    for nonce in count():
        header = prefix + nonce.to_bytes(4, "little")
        if int.from_bytes(hash256(header), "little") <= REGTEST_TARGET:
            return header


class SpvPaymentTest(unittest.TestCase):
    def setUp(self):
        self.parent = Transaction((Input(bytes([1]) * 32, 0),), (Output(1000, b"\x51"),))
        self.payment = Transaction((Input(self.parent.txid_wire(), 0),), (Output(900, b"\x51"),))
        self.txids = (self.parent.txid_wire(), self.payment.txid_wire())
        header = child_header(GENESIS, hash256(b"".join(self.txids)))
        self.chain = RegtestHeaderChain((GENESIS, header))
        self.parent_packet = TxInclusion(self.parent.serialize(), BlockInclusion.from_block(header, 1, self.txids, 0))
        self.payment_packet = TxInclusion(self.payment.serialize(), BlockInclusion.from_block(header, 1, self.txids, 1))

    def verify(self, **changes):
        options = dict(txid_wire=self.payment.txid_wire(), vout=0, expected_output=self.payment.outputs[0],
                       authenticate=lambda tx, parents: tx == self.payment and parents == {self.txids[0]: self.parent},
                       activation_height=2)
        return verify_receipt(changes.pop("chain", self.chain), changes.pop("payment", self.payment_packet),
                              changes.pop("parents", (self.parent_packet,)), **(options | changes))

    def test_same_block_parent_and_receipt(self):
        receipt = self.verify()
        self.assertEqual(receipt.outpoint, self.payment.txid_wire() + bytes(4))
        self.assertEqual((receipt.confirmations, receipt.fee, receipt.spend_status), (1, 100, SpendStatus.UNKNOWN))
        with self.assertRaisesRegex(ValueError, "insufficient confirmations"):
            self.verify(minimum_confirmations=2)

    def test_exact_parent_and_invoice(self):
        cases = (("missing actual parent", {"parents": ()}),
                 ("excess parent data", {"parents": (self.parent_packet, self.parent_packet)}),
                 ("extraneous", {"parents": (self.payment_packet,)}),
                 ("outpoint", {"vout": 1}),
                 ("unauthorized", {"authenticate": lambda *_: False}))
        for message, changes in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.verify(**changes)

    def test_merkle_and_adopted_header(self):
        broken = replace(self.payment_packet.inclusion, siblings=(bytes(32),))
        with self.assertRaisesRegex(ValueError, "invalid transaction Merkle inclusion"):
            self.verify(payment=replace(self.payment_packet, inclusion=broken))
        fork = child_header(GENESIS, bytes(32))
        fork_chain = RegtestHeaderChain((GENESIS, fork))
        self.assertIs(self.chain.adopt(fork_chain), self.chain)
        with self.assertRaisesRegex(ValueError, "outside the adopted header chain"):
            self.verify(chain=fork_chain)
        next_header = child_header(fork, bytes(32))
        longer = RegtestHeaderChain((GENESIS, fork, next_header))
        self.assertIs(self.chain.adopt(longer), longer)


if __name__ == "__main__":
    unittest.main()

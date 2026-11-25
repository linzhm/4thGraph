from dataclasses import replace
import unittest

from operational_token import TokenPolicy
from shared.pushtx import PUBLIC
from shared.script import asm
from shared.transaction import Input, Output, Transaction, hash256
from statement import AssetDescriptor
from transaction_relation import TokenState
from wallet_receipt import BlockInclusion, SpendStatus, verify_payment


class WalletReceiptTests(unittest.TestCase):
    def setUp(self):
        self.policy = TokenPolicy((asm("OP_1"),), PUBLIC)
        self.asset = AssetDescriptor(1, bytes(36), 6, 7, b"r" * 32, b"p" * 32)
        state = TokenState(self.asset.asset_id(), 384, PUBLIC)
        self.tx = Transaction((Input(b"u" * 32, 0),), (Output(1, b"\x51"), Output(1000, self.policy.lock(state))))
        first, second, last = b"a" * 32, b"b" * 32, self.tx.txid_wire()
        merkle_root = hash256(hash256(first + second) + hash256(last + last))
        self.inclusion = BlockInclusion.from_block(bytes(36) + merkle_root + bytes(12),
                                                   128, (first, second, last), 2)

    def verify(self, **changes):
        parameters = {
            "transaction": self.tx, "vout": 1, "asset": self.asset, "policy": self.policy,
            "inclusion": self.inclusion, "expected_owner": PUBLIC, "minimum_confirmations": 2,
            "adopted_depth": lambda height, block_hash: (
                3 if height == 128 and block_hash == self.inclusion.block_hash() else None
            ),
            "valid_creation": lambda tx, vout: tx == self.tx and vout == 1,
            "lookup_spend": lambda _: SpendStatus.UNKNOWN,
        }
        return verify_payment(**(parameters | changes))

    def test_same_inclusion_supports_independent_spend_observations(self):
        for status in SpendStatus:
            with self.subTest(status=status):
                calls = []

                def lookup(outpoint):
                    calls.append(outpoint)
                    return status

                result = self.verify(lookup_spend=lookup)
                outpoint = self.tx.txid_wire() + b"\x01\x00\x00\x00"
                self.assertEqual(calls, [outpoint])
                self.assertEqual((result.outpoint, result.quantity, result.confirmations, result.spend_status),
                                 (outpoint, 384, 3, status))

    def test_wrong_vout_adopted_chain_merkle_branch_and_unproven_creation(self):
        variants = [
            ({"vout": 0}, "wrong asset"),
            ({"adopted_depth": lambda *_: None}, "outside the adopted chain"),
            ({"minimum_confirmations": 4}, "not confirmed"),
            ({"inclusion": replace(self.inclusion, siblings=self.inclusion.siblings[1:])}, "Merkle sibling"),
            ({"valid_creation": lambda *_: False}, "unauthenticated output"),
        ]
        for changes, expected in variants:
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, expected):
                self.verify(**changes)

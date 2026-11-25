"""Real local EVM receipt integration. Requires forge, cast, and anvil on PATH."""

import unittest

from evm.anvil_fixture import (
    BSV_NETWORK, CHAIN_ID, HAS_FOUNDRY, RESERVE_DOMAIN, address_for_key,
    deposit_position, sign_digest_for_test, start_anvil,
)
from evm.mint_adapter import finalized_deposit_reader
from evm.reserve_rpc import DepositEvidenceError, ReserveScope

OWNER = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


@unittest.skipUnless(HAS_FOUNDRY, "requires Foundry")
class ReserveAnvilTest(unittest.TestCase):
    def test_finality_and_live_deposit_release_receipts(self):
        with start_anvil() as evm:
            self._run_round_trip(evm)

    def _run_round_trip(self, evm):
        accounts = evm.accounts()
        admin, guardian, depositor, recipient, treasury = accounts[:5]
        # Public test-only key. Production authorizers supply an external signer.
        signer_key = "0x" + (0xC0FFEE).to_bytes(32, "big").hex()
        signer = address_for_key(signer_key)
        asset_id = "0x" + bytes([0x42] * 32).hex()
        token = evm.deploy("test/TestUsdcReserve.t.sol:MockUsdc", admin)
        vault = evm.deploy(
            "src/TestUsdcReserve.sol:TestUsdcReserve", admin,
            f"({CHAIN_ID},{RESERVE_DOMAIN},{BSV_NETWORK},{asset_id},{token},{admin},{guardian},{signer},{treasury})",
        )
        evm.send(token, "mint(address,uint256)", depositor, "1024", sender=admin)
        evm.send(token, "approve(address,uint256)", vault, "1024", sender=depositor)
        receipt = evm.send(vault, "deposit(uint64,bytes)", "1024", OWNER, sender=depositor)

        scope = ReserveScope(
            CHAIN_ID, RESERVE_DOMAIN, BSV_NETWORK,
            bytes.fromhex(vault[2:]), bytes.fromhex(token[2:]), bytes.fromhex(asset_id[2:]),
        )
        position = deposit_position(receipt, vault)
        self.assertEqual(position.log_ordinal, 1)
        observe = finalized_deposit_reader(evm.rpc, scope)
        with self.assertRaisesRegex(DepositEvidenceError, "not finalized"):
            observe(position)
        evm.mine_finality()
        deposit = observe(position)
        self.assertEqual(deposit.owner, bytes.fromhex(OWNER[2:]))
        self.assertEqual(deposit.net_quantity, 1024)

        # Synthetic BSV evidence scoped to this EVM test of the release boundary.
        txid = "0x" + (b"t" * 32).hex()
        block_hash = "0x" + (b"b" * 32).hex()
        request = f"({BSV_NETWORK},{txid},1,{block_hash},{asset_id},{RESERVE_DOMAIN},{recipient},640,0,1)"
        ordered_fields = "(uint32,bytes32,uint32,bytes32,bytes32,uint32,address,uint64,uint64,uint64)"
        digest = evm.call(vault, f"releaseDigest({ordered_fields})(bytes32)", request)
        signature = sign_digest_for_test(signer_key, digest)
        evm.send(vault, f"release({ordered_fields},bytes)", request, signature, sender=depositor)
        self.assertEqual(evm.call(vault, "netReserve()(uint256)"), "384")
        self.assertEqual(evm.call(token, "balanceOf(address)(uint256)", recipient), "640")
        self.assertEqual(evm.call(token, "balanceOf(address)(uint256)", vault), "384")


if __name__ == "__main__":
    unittest.main()

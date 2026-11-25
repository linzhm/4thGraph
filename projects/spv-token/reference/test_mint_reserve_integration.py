"""Finalized Anvil reserve deposit to an independent BSV regtest block."""

from hashlib import new, sha256
import json
import os
from pathlib import Path
import unittest

from mint import MintPolicy, authorize_mint, prepare_mint, read_deposit, recover_events
from mint_events import Deposit, EMPTY_ROOT, MintEvents
from operational_token import TokenPolicy
from evm.anvil_fixture import BSV_NETWORK, CHAIN_ID, HAS_FOUNDRY, RESERVE_DOMAIN, deposit_position, start_anvil
from evm.mint_adapter import finalized_deposit_reader
from evm.reserve_rpc import DepositEvidenceError, ReserveScope
from regtest_mint import Node, base58check, sign_p2pkh
from shared.script import asm
from shared.transaction import Input, Output, Transaction
from statement import AssetDescriptor
from test_mint import ATTESTOR, OTHER, OWNER, public, sign


@unittest.skipUnless(HAS_FOUNDRY and os.environ.get("CCTP_MINT_REGTEST_COOKIE"),
                     "requires Foundry plus independent BSV regtest")
class ReserveMintIntegration(unittest.TestCase):
    def test_confirmed_reserve_deposit_mints_its_exact_bsv_output(self):
        node = Node(os.environ.get("CCTP_MINT_REGTEST_URL", "http://127.0.0.1:19444"),
                    Path(os.environ["CCTP_MINT_REGTEST_COOKIE"]))
        owner = public(OWNER)
        owner_hash = new("ripemd160", sha256(owner).digest()).digest()
        address = base58check(b"\x6f" + owner_hash)
        coinbase = node.fund(address)
        funding = Transaction((Input(coinbase.txid_wire(), 0),), (Output(200_000, asm("OP_1")),) * 2)
        funding = sign_p2pkh(funding, coinbase, 0, OWNER)
        node.confirm(funding, address)
        anchor, sponsor = (Input(funding.txid_wire(), index) for index in range(2))

        with start_anvil() as evm:
            admin, guardian, depositor, release_signer, treasury = evm.accounts()[:5]
            usdc = evm.deploy("test/TestUsdcReserve.t.sol:MockUsdc", admin)
            usdc_address = bytes.fromhex(usdc[2:])
            # The real bridge descriptor uses the already created BSV issuance anchor.
            asset = AssetDescriptor(BSV_NETWORK, anchor.outpoint(), 6, RESERVE_DOMAIN,
                                    usdc_address.rjust(32, b"\x00"), b"i" * 32)
            asset_id = asset.asset_id()
            vault = evm.deploy(
                "src/TestUsdcReserve.sol:TestUsdcReserve", admin,
                f"({CHAIN_ID},{RESERVE_DOMAIN},{BSV_NETWORK},0x{asset_id.hex()},"
                f"{usdc},{admin},{guardian},{release_signer},{treasury})",
            )
            scope = ReserveScope(CHAIN_ID, RESERVE_DOMAIN, BSV_NETWORK,
                                 bytes.fromhex(vault[2:]), usdc_address, asset_id)
            # This integration exercises mint creation and token lock identity.
            # A transfer verifier is supplied by the separate lifecycle harness.
            token_policy = TokenPolicy((asm("OP_1"),), public(OTHER))
            policy = MintPolicy(asset, CHAIN_ID, scope.vault, public(ATTESTOR), token_policy.lock,
                                pause_authority=public(OTHER))
            genesis = Transaction((anchor,), (Output(100_000, policy.state_lock(EMPTY_ROOT)),))
            node.confirm(genesis, address)

            evm.send(usdc, "mint(address,uint256)", depositor, "1024", sender=admin)
            evm.send(usdc, "approve(address,uint256)", vault, "1024", sender=depositor)
            receipt = evm.send(vault, "deposit(uint64,bytes)", "1024", "0x" + owner.hex(), sender=depositor)
            position = deposit_position(receipt, vault)
            deposit = Deposit(position, asset.reserve_asset, BSV_NETWORK, asset_id, 1024, 0, owner)
            plan = prepare_mint(policy, genesis, MintEvents(), deposit, sponsor)
            observe = finalized_deposit_reader(evm.rpc, scope)
            signing_calls = []

            def sign_observed(digest):
                signing_calls.append(digest)
                return sign(digest)

            with self.assertRaisesRegex(DepositEvidenceError, "not finalized"):
                authorize_mint(plan, observe, sign_observed)
            self.assertEqual(signing_calls, [])

            evm.mine_finality()
            mint = authorize_mint(plan, observe, sign_observed)
            self.assertEqual(len(signing_calls), 1)
            node.confirm(mint, address)
            tx_record = node.call("getrawtransaction", mint.txid(), True)
            mined = Transaction.parse(bytes.fromhex(tx_record["hex"]))
            self.assertEqual(read_deposit(mined), deposit)
            token = token_policy.parse(mined.outputs[1].script)
            self.assertEqual((token.quantity, token.owner, token.asset_id, token.frozen),
                             (1024, owner, asset_id, False))
            self.assertEqual(recover_events(policy, genesis, (mined,)), plan.successor)
            self.assertEqual(evm.call(vault, "netReserve()(uint256)"), "1024")

            if os.environ.get("CCTP_RESERVE_MINT_REPORT"):
                report = {
                    "source": {"node": "Anvil", "chain_id": CHAIN_ID, "reserve_contract": vault,
                               "tx_hash": receipt["transactionHash"], "block": receipt["blockHash"],
                               "receipt_log_ordinal": position.log_ordinal, "net_reserve": 1024},
                    "bsv": {"node": node.call("getnetworkinfo")["subversion"], "genesis_txid": genesis.txid(),
                            "mint_txid": mined.txid(), "block": tx_record["blockhash"], "vout": 1,
                            "minted_quantity": token.quantity},
                    "deposit_event_id": position.event_id().hex(),
                    "bridge_asset_id": asset_id.hex(),
                    "signer_calls_before_source_finality": 0,
                }
                Path(os.environ["CCTP_RESERVE_MINT_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")

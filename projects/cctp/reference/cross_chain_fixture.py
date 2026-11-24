"""Anvil reserve and adopted BSV chain helpers for the lifecycle regression."""
from http.client import IncompleteRead, RemoteDisconnected
import json
import subprocess

from confirmed_lineage import ConfirmedLineage
from mint_events import Deposit
from projects.cctp.evm.anvil_fixture import (
    BSV_NETWORK, CHAIN_ID, RESERVE_DOMAIN, address_for_key, deposit_position, sign_digest_for_test,
)
from projects.cctp.evm.bsv_burn_evidence import BsvConfirmationPolicy, BurnReference
from projects.cctp.evm.mint_adapter import finalized_deposit_reader
from projects.cctp.evm.release_adapter import ReleaseAuthorization, Settlement, authorize_release, read_settlement
from projects.cctp.evm.reserve_rpc import ReserveScope
from statement import AssetDescriptor
from wallet_receipt import BlockInclusion, SpendStatus, verify_payment


class LocalReserve:
    def __init__(self, evm, issuance_outpoint):
        self.evm = evm
        self.admin, guardian, self.depositor, _, treasury = evm.accounts()[:5]
        # Disposable test signer. A separate account broadcasts Anvil transactions.
        self.test_signing_key = "0x" + "11" * 32
        release_signer = address_for_key(self.test_signing_key)
        self.usdc = evm.deploy("test/TestUsdcReserve.t.sol:MockUsdc", self.admin)
        usdc = bytes.fromhex(self.usdc[2:])
        self.asset = AssetDescriptor(BSV_NETWORK, issuance_outpoint, 6, RESERVE_DOMAIN,
                                     usdc.rjust(32, b"\0"), b"p" * 32)
        asset_id = self.asset.asset_id()
        self.vault = evm.deploy(
            "src/TestUsdcReserve.sol:TestUsdcReserve", self.admin,
            f"({CHAIN_ID},{RESERVE_DOMAIN},{BSV_NETWORK},0x{asset_id.hex()},"
            f"{self.usdc},{self.admin},{guardian},{release_signer},{treasury})",
        )
        self.scope = ReserveScope(CHAIN_ID, RESERVE_DOMAIN, BSV_NETWORK, bytes.fromhex(self.vault[2:]), usdc, asset_id)
        self.observe = finalized_deposit_reader(evm.rpc, self.scope)
        self.recipient = bytes.fromhex(self.depositor[2:])

    def deposit(self, quantity, owner):
        evm = self.evm
        evm.send(self.usdc, "mint(address,uint256)", self.depositor, str(quantity), sender=self.admin)
        evm.send(self.usdc, "approve(address,uint256)", self.vault, str(quantity), sender=self.depositor)
        receipt = evm.send(self.vault, "deposit(uint64,bytes)", str(quantity), "0x" + owner.hex(), sender=self.depositor)
        position = deposit_position(receipt, self.vault)
        evm.mine_finality()
        expected = Deposit(position, self.asset.reserve_asset, BSV_NETWORK, self.asset.asset_id(), quantity, 0, owner)
        if self.observe(position) != expected:
            raise AssertionError("finalized deposit does not match the requested reserve deposit")
        evidence = {"txid": receipt["transactionHash"], "blockhash": receipt["blockHash"],
                    "event_id": position.event_id().hex(), "receipt_log_ordinal": position.log_ordinal,
                    "quantity": quantity}
        return expected, evidence

    def release(self, chain, tx, vout, lineage):
        bsv = chain.call
        record = chain.load(tx.txid_wire())
        if record is None:
            raise AssertionError("burn is missing from the adopted BSV chain")
        block_hash = bytes.fromhex(record["blockhash"])[::-1]
        policy = BsvConfirmationPolicy(self.asset.network, "regtest", bytes.fromhex(bsv("getblockhash", 0))[::-1], 2)
        reference = BurnReference(tx.txid_wire(), vout, block_hash, record["height"])

        def proven(burn, asset):
            return (asset == self.asset and burn.transaction == tx
                    and lineage.burn(tx.txid_wire(), vout) == burn.receipt)

        def sign(digest):
            return bytes.fromhex(sign_digest_for_test(self.test_signing_key, "0x" + digest.hex())[2:])

        def authorize(signer):
            return authorize_release(bsv, self.evm.rpc, policy, self.scope, self.asset, reference,
                                     verify_provenance=proven, sign_digest=signer)

        authorization = authorize(sign)
        if not isinstance(authorization, ReleaseAuthorization):
            raise AssertionError("new burn was already settled")
        before = self._uint_call(self.usdc, "balanceOf(address)(uint256)", self.depositor)
        send = subprocess.run(
            ["cast", "send", "--rpc-url", self.evm.url, "--from", self.admin, "--unlocked",
             "--json", "--data", "0x" + authorization.calldata().hex(), self.vault],
            check=True, capture_output=True, text=True, timeout=50,
        )
        receipt = json.loads(send.stdout)
        if receipt["status"] != "0x1":
            raise AssertionError("authorized release did not settle")
        self.evm.mine_finality()
        settlement = read_settlement(self.evm.rpc, self.scope, reference)
        if not isinstance(settlement, Settlement) or not settlement.finalized:
            raise AssertionError("release did not become finalized")
        after = self._uint_call(self.usdc, "balanceOf(address)(uint256)", self.depositor)
        if after - before != authorization.claim.quantity - authorization.claim.fee:
            raise AssertionError("reserve release did not credit the authorized recipient and amount")

        def unexpected_sign(_):
            raise AssertionError("settled release reached the signing service")

        replay = authorize(unexpected_sign)
        if replay != settlement:
            raise AssertionError("restart did not recover the original settlement")
        return {
            "txid": receipt["transactionHash"], "blockhash": receipt["blockHash"],
            "burn_txid": tx.txid(), "burn_vout": vout, "burn_blockhash": record["blockhash"],
            "burn_event_id": settlement.burn_id.hex(), "attestation_digest": settlement.digest.hex(),
            "confirmation_depth_policy": policy.minimum_confirmations,
            "quantity": authorization.claim.quantity, "actual_recipient_credit": after - before,
            "finalized": settlement.finalized, "recovered_without_resigning": True,
        }

    def _uint_call(self, contract, function, *args):
        return int(self.evm.call(contract, function, *args), 0)

    def accounting(self, minted, burned, circulating):
        deposited = self._uint_call(self.vault, "totalDeposited()(uint256)")
        released = self._uint_call(self.vault, "totalReleased()(uint256)")
        net = self._uint_call(self.vault, "netReserve()(uint256)")
        balance = self._uint_call(self.usdc, "balanceOf(address)(uint256)", self.vault)
        if not (deposited >= minted and burned >= released and minted - burned == circulating
                and net == balance == deposited - released):
            raise AssertionError("BSV supply and EVM reserve accounting disagree")
        pending_mint = deposited - minted
        pending_release = burned - released
        if net != pending_mint + circulating + pending_release:
            raise AssertionError("reserve and supply invariant failed")
        return {
            "deposited": deposited, "minted": minted, "burned": burned, "released": released,
            "net_reserve": net, "actual_vault_balance": balance, "bsv_circulating": circulating,
            "pending_mint": pending_mint, "pending_release": pending_release,
        }


class AdoptedBsvChain:
    """Use one active Node tip for confirmed ancestry, block paths and spend observations."""

    def __init__(self, node, confirmed_blocks):
        self._call = node.call
        chain = self.call("getblockchaininfo")
        self.height = chain["blocks"]
        self.tip = chain["bestblockhash"]
        self.confirmed_blocks = dict(confirmed_blocks)
        self.records = {}

    def call(self, method, *args):
        # An independent node may close a large chunked response. Retry reads
        # only. Transaction submission and block generation use the direct RPC.
        for attempt in range(3):
            try:
                return self._call(method, *args)
            except (IncompleteRead, RemoteDisconnected, ConnectionResetError, TimeoutError):
                if attempt == 2:
                    raise

    def check_tip(self):
        if self.call("getblockhash", self.height) != self.tip:
            raise ValueError("adopted BSV tip changed during provenance verification")

    def depth(self, height, block_hash):
        self.check_tip()
        if height > self.height or self.call("getblockhash", height) != block_hash[::-1].hex():
            return None
        return self.height - height + 1

    def load(self, txid_wire):
        self.check_tip()
        if txid_wire not in self.records:
            block_hash = self.confirmed_blocks.get(txid_wire)
            if block_hash is None:
                return None
            txid = txid_wire[::-1].hex()
            block = self.call("getblock", block_hash, 1)
            height = block["height"]
            if txid not in block["tx"] or not self.depth(height, bytes.fromhex(block_hash)[::-1]):
                return None
            raw = bytes.fromhex(self.call("getrawtransaction", txid, False))
            self.records[txid_wire] = {"blockhash": block_hash, "height": height, "raw": raw}
        return self.records[txid_wire]

    def raw(self, txid_wire):
        record = self.load(txid_wire)
        return record["raw"] if record else None

    def lineage(self, mint, token, provers):
        return ConfirmedLineage(mint, token, tuple((p.profile, p.key) for p in provers), self.raw)

    def spend(self, outpoint):
        self.check_tip()
        txid, vout = outpoint[:32][::-1].hex(), int.from_bytes(outpoint[32:], "little")
        # Callers already authenticated a specific confirmed, spendable token output.
        output = self.call("gettxout", txid, vout, False)
        return SpendStatus.UNSPENT if output is not None else SpendStatus.SPENT

    def payment(self, tx, vout, asset, token, lineage, owner):
        record = self.load(tx.txid_wire())
        if record is None:
            raise ValueError("wallet payment is missing from the adopted BSV chain")
        block_hash = record["blockhash"]
        block = self.call("getblock", block_hash, 1)
        header = bytes.fromhex(self.call("getblockheader", block_hash, False))
        txids = tuple(bytes.fromhex(txid)[::-1] for txid in block["tx"])
        inclusion = BlockInclusion.from_block(header, block["height"], txids, txids.index(tx.txid_wire()))
        receipt = verify_payment(
            tx, vout, asset, token, inclusion, adopted_depth=self.depth,
            valid_creation=lineage.valid_creation, lookup_spend=self.spend, expected_owner=owner,
        )
        evidence = {
            "txid": tx.txid(), "vout": vout, "outpoint_wire": receipt.outpoint.hex(),
            "quantity": receipt.quantity, "confirmations": receipt.confirmations,
            "known_spend_status": receipt.spend_status.value, "frozen": receipt.frozen,
            "blockhash": block_hash, "block_header": header.hex(), "block_height": inclusion.height,
            "block_leaf_count": inclusion.leaf_count, "merkle_index": inclusion.index,
            "merkle_siblings_wire": [sibling.hex() for sibling in inclusion.siblings],
        }
        return receipt, evidence

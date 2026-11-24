"""Anvil reserve and adopted BSV chain helpers for the lifecycle regression."""
from http.client import IncompleteRead, RemoteDisconnected
import json
import subprocess

from bridge_ledger import BridgeLedger, ChainReference
from bridge_service import BridgeService
from confirmed_lineage import ConfirmedLineage
from mint import recover_mint_state
from mint_events import Deposit
from projects.cctp.evm.anvil_fixture import (
    BSV_NETWORK, CHAIN_ID, RESERVE_DOMAIN, address_for_key, deposit_position, sign_digest_for_test,
)
from projects.cctp.evm.bsv_burn_evidence import BsvConfirmationPolicy, BurnReference
from projects.cctp.evm.mint_adapter import finalized_deposit_reader
from projects.cctp.evm.release_adapter import ReleaseAuthorization, Settlement, _hash, burn_event_id
from projects.cctp.evm.reserve_rpc import ReserveScope
from shared.transaction import Transaction
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

    def uint_call(self, contract, function, *args):
        return int(self.evm.call(contract, function, *args), 0)


class _SignerInterrupted(TimeoutError):
    """Fixture-side failure after the authorization was durably reserved."""


class DurableBridge:
    def __init__(self, reserve, mint_policy, path):
        self.reserve = reserve
        self.mint_policy = mint_policy
        self.path = path

    def reopen(self):
        scope = self.reserve.scope
        ledger = BridgeLedger(self.path, self.reserve.asset, scope.chain_id, scope.vault)
        return BridgeService(ledger, self.mint_policy, scope, self.reserve.evm.rpc)

    def _authorize_with_restart(self, event_id, authorize, signer, *, interrupt, resume=None):
        signed_digests = []
        resume = resume or authorize

        def check_intent(digest):
            # Separate SQLite handles prove the signing intent was committed.
            ledger = self.reopen().ledger
            state = ledger.state(event_id)
            if (state is None or state.phase != "authorized" or state.authorization != digest
                    or not state.origin_confirmed or state.effect is not None
                    or ledger.authorization_signature(event_id, digest) is not None):
                raise AssertionError("external signer called without a durable, finalized authorization")

        def interrupted(digest):
            check_intent(digest)
            raise _SignerInterrupted("fixture signer did not return a signature")

        if interrupt:
            try:
                authorize(self.reopen(), interrupted)
            except _SignerInterrupted:
                pass
            else:
                raise AssertionError("expected interruption before the signature was returned")

        def sign(digest):
            check_intent(digest)
            signed_digests.append(digest)
            return signer(digest)

        result = (resume if interrupt else authorize)(self.reopen(), sign)
        recovered = resume(self.reopen(), self._unexpected_sign)
        if result != recovered or len(signed_digests) != 1:
            raise AssertionError("restart did not recover the exact authorization")
        digest, = signed_digests
        state = self.reopen().ledger.state(event_id)
        return result, {
            "event_id": event_id.hex(), "authorization_digest": digest.hex(),
            "phase_before_broadcast": state.phase, "signer_interrupted": interrupt,
            "pre_sign_intent_persisted": True, "recovered_signature_without_resigning": True,
        }

    @staticmethod
    def _unexpected_sign(_digest):
        raise AssertionError("durably authorized action reached the signer again")

    def authorize_mint(self, plan, load_state, signer, *, interrupt=False):
        event_id = plan.deposit.position.event_id()
        result, journal = self._authorize_with_restart(
            event_id, lambda service, callback: service.authorize_mint(plan, load_state, callback),
            signer, interrupt=interrupt,
            resume=lambda service, callback: service.recover_mint(event_id, load_state, callback),
        )
        return result, journal | {"reconstructed_from_persisted_draft": True}

    def record_mint(self, chain, tx, predecessor, event_id):
        reference = chain.reference(tx, 1)
        recorded = self.reopen().record_mint(chain.call, chain.confirmation_policy(self.reserve.asset), reference,
                                             predecessor)
        state = self.reopen().ledger.state(event_id)
        if recorded != event_id or state.phase != "settled" or state.effect != reference or not state.effect_confirmed:
            raise AssertionError("confirmed mint did not settle its journalled deposit")
        return {
            "bsv_txid": tx.txid(), "bsv_blockhash": reference.block_hash[::-1].hex(),
            "bsv_vout": reference.position, "bsv_height": reference.height,
            "phase_after_confirmation": state.phase,
        }

    def release(self, chain, tx, vout, lineage, *, circulating, interrupt=False):
        reserve = self.reserve
        evm = reserve.evm
        policy = chain.confirmation_policy(reserve.asset)
        position = chain.reference(tx, vout)
        reference = BurnReference(position.txid, position.position, position.block_hash, position.height)

        def sign(digest):
            return bytes.fromhex(sign_digest_for_test(reserve.test_signing_key, "0x" + digest.hex())[2:])

        def authorize(service, signer):
            return service.authorize_release(chain.call, policy, reference, lineage, signer)

        event_id = burn_event_id(reserve.asset.network, reference)
        authorization, journal = self._authorize_with_restart(event_id, authorize, sign, interrupt=interrupt)
        if not isinstance(authorization, ReleaseAuthorization):
            raise AssertionError("new burn was already settled")
        before = reserve.uint_call(reserve.usdc, "balanceOf(address)(uint256)", reserve.depositor)
        pending = self.reconcile(circulating, 0)
        if pending["pending_release"] != authorization.claim.quantity:
            raise AssertionError("journal did not count the authorized, unpaid burn")
        send = subprocess.run(
            ["cast", "send", "--rpc-url", evm.url, "--from", reserve.admin, "--unlocked",
             "--json", "--data", "0x" + authorization.calldata().hex(), reserve.vault],
            check=True, capture_output=True, text=True, timeout=50,
        )
        receipt = json.loads(send.stdout)
        if receipt["status"] != "0x1":
            raise AssertionError("authorized release did not settle")
        release_topic = "0x" + _hash(b"Release(bytes32,bytes32,address,uint32,uint64,uint64,bytes32)").hex()
        ordinal, = [
            i for i, log in enumerate(receipt["logs"])
            if log["address"].lower() == reserve.vault.lower() and log["topics"][0] == release_topic
        ]
        effect = ChainReference(
            bytes.fromhex(receipt["transactionHash"][2:]), ordinal,
            bytes.fromhex(receipt["blockHash"][2:]), int(receipt["blockNumber"], 16),
        )
        submitted = self.reopen().record_release(effect, reference)
        if submitted.phase != "submitted" or submitted.effect_confirmed or submitted.effect != effect:
            raise AssertionError("nonfinal release was not recorded solely as submitted")
        evm.mine_finality()
        recorded = self.reopen().record_release(effect, reference)
        if recorded.phase != "settled" or not recorded.effect_confirmed or recorded.effect != effect:
            raise AssertionError("finalized payout did not settle the durable event")
        settled = authorize(self.reopen(), self._unexpected_sign)
        if settled != Settlement(event_id, authorization.digest, finalized=True):
            raise AssertionError("restart did not recover the original settlement")
        after = reserve.uint_call(reserve.usdc, "balanceOf(address)(uint256)", reserve.depositor)
        if after - before != authorization.claim.quantity - authorization.claim.fee:
            raise AssertionError("reserve release did not credit the authorized recipient and amount")
        return {
            "txid": receipt["transactionHash"], "blockhash": receipt["blockHash"],
            "receipt_log_ordinal": ordinal, "burn_txid": tx.txid(), "burn_vout": vout,
            "burn_blockhash": position.block_hash[::-1].hex(),
            "burn_event_id": event_id.hex(), "attestation_digest": authorization.digest.hex(),
            "confirmation_depth_policy": policy.minimum_confirmations,
            "quantity": authorization.claim.quantity, "actual_recipient_credit": after - before,
            "finalized": True, "recovered_without_resigning": True,
            "journal": journal | {"observed_effect_phase": submitted.phase, "final_effect_phase": recorded.phase},
            "before_broadcast_accounting": pending,
        }

    def reconcile(self, circulating, frozen):
        reserve = self.reserve
        deposited = reserve.uint_call(reserve.vault, "totalDeposited()(uint256)")
        released = reserve.uint_call(reserve.vault, "totalReleased()(uint256)")
        net = reserve.uint_call(reserve.vault, "netReserve()(uint256)")
        balance = reserve.uint_call(reserve.usdc, "balanceOf(address)(uint256)", reserve.vault)
        result = self.reopen().reconcile(source_balance=balance, live_supply=circulating, frozen_supply=frozen)
        totals = result.totals
        if (not result.may_authorize or net != balance
                or (deposited, released) != (totals.finalized_deposits, totals.released)):
            raise AssertionError("bridge journal disagrees with the independent chain observations")
        return {
            "deposited": deposited, "minted": totals.minted, "burned": totals.burned, "released": released,
            "net_reserve": net, "actual_vault_balance": balance, "bsv_circulating": circulating,
            "bsv_frozen": frozen, "pending_mint": totals.pending_mint, "pending_release": totals.pending_release,
            "balanced": result.balanced, "holds": len(result.holds),
        }

    def audit(self):
        return [
            {"sequence": seq, "event_id": event_id.hex() if event_id else None, "operation": operation}
            for seq, event_id, operation, _ in self.reopen().ledger.audit_log()
        ]


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

    def confirmation_policy(self, asset):
        return BsvConfirmationPolicy(asset.network, "regtest", bytes.fromhex(self.call("getblockhash", 0))[::-1], 2)

    def reference(self, tx, vout):
        record = self.load(tx.txid_wire())
        if record is None or record["raw"] != tx.serialize():
            raise ValueError("transaction is missing from the adopted BSV chain")
        return ChainReference(tx.txid_wire(), vout, bytes.fromhex(record["blockhash"])[::-1], record["height"])

    def mint_state(self, mint_policy, genesis, transitions=()):
        confirmed = []
        for tx in (genesis, *transitions):
            reference = self.reference(tx, 0)
            if self.depth(reference.height, reference.block_hash) < 2:
                raise ValueError("mint state is not sufficiently confirmed")
            confirmed.append(Transaction.parse(self.raw(tx.txid_wire())))
        state = recover_mint_state(mint_policy, confirmed[0], tuple(confirmed[1:]))
        if self.spend(state.transaction.txid_wire() + bytes(4)) != SpendStatus.UNSPENT:
            raise ValueError("confirmed mint state output has already been spent")
        return state

    def supply(self, lineage, *outpoints):
        circulating = frozen = 0
        for tx, vout in outpoints:
            state = lineage.token(tx.txid_wire(), vout)
            if self.spend(tx.txid_wire() + vout.to_bytes(4, "little")) != SpendStatus.UNSPENT:
                raise AssertionError("circulation fixture references a spent token")
            circulating += state.quantity
            if state.frozen:
                frozen += state.quantity
        return circulating, frozen

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

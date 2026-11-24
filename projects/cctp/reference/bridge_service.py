"""Bridge authorization service over independently validated BSV and EVM data."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
from collections.abc import Callable

from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

from bridge_ledger import BridgeLedger, ChainReference, EventState
from confirmed_lineage import ConfirmedLineage
from mint import MintPlan, MintPolicy, RecoveredMintState, authorize_mint, prepare_mint, read_deposit
from mint_events import Deposit, DepositPosition
from projects.cctp.evm.bsv_burn_evidence import (
    BsvConfirmationPolicy, BurnReference, CanonicalBurn, require_canonical_burn_block,
)
from projects.cctp.evm.release_adapter import (
    ReleaseAuthorization, Settlement, _hash, authorize_release, burn_event_id, read_settlement,
)
from projects.cctp.evm.reserve_rpc import ReserveScope, Rpc, _data, _object, _quantity, read_finalized_deposit
from shared.transaction import Transaction, hash256, preimage_all

_RELEASE_TOPIC = _hash(b"Release(bytes32,bytes32,address,uint32,uint64,uint64,bytes32)")
DigestSigner = Callable[[bytes], bytes]


@contextmanager
def _exclusive_signature_cache(path):
    # SQLite commits the intent independently of the outbound signing RPC.
    # The advisory lock serializes cache reads and writes across workers.
    fd = os.open(path + ".signing.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _verify_bsv_signature(key: bytes, digest: bytes, signature: bytes) -> None:
    signer = VerifyingKey.from_string(key, curve=SECP256k1, valid_encodings={"compressed"})
    try:
        valid = signer.verify_digest(signature, digest, sigdecode=sigdecode_der)
    except (BadSignatureError, ValueError) as error:
        raise ValueError("external mint signer returned an invalid signature") from error
    if not valid:
        raise ValueError("external mint signer returned an invalid signature")
    _, s = sigdecode_der(signature, SECP256k1.order)
    if s > SECP256k1.order // 2:
        raise ValueError("external mint signer returned a noncanonical signature")


@dataclass(frozen=True)
class BridgeService:
    """Authorize or recover one exact action. Broadcasting remains external."""

    ledger: BridgeLedger
    mint_policy: MintPolicy
    reserve_scope: ReserveScope
    evm_rpc: Rpc

    def __post_init__(self):
        ledger, policy, scope = self.ledger, self.mint_policy, self.reserve_scope
        asset = policy.asset
        if (ledger.asset != asset or scope.asset_id != asset.asset_id()
                or scope.bsv_network != asset.network or scope.reserve_domain != asset.reserve_domain
                or bytes(12) + scope.reserve_asset != asset.reserve_asset
                or not ledger.source_chain_id == policy.source_chain_id == scope.chain_id
                or not ledger.reserve_contract == policy.reserve_contract == scope.vault):
            raise ValueError("bridge service scopes are inconsistent")

    def _check_evm_origin(self, event_id: bytes, *, effect: bool = False) -> None:
        state = self.ledger.state(event_id)
        if state is None:
            return
        reference = state.effect if effect else state.origin
        if reference is None or state.phase == "orphaned":
            return
        if _quantity(self.evm_rpc("eth_chainId"), "RPC chain ID") != self.reserve_scope.chain_id:
            raise ValueError("unexpected EVM chain during reorg check")
        block = _object(self.evm_rpc("eth_getBlockByNumber", hex(reference.height), False), "EVM block")
        if _quantity(block.get("number"), "EVM block number") != reference.height:
            raise ValueError("unexpected EVM block height")
        canonical_hash = _data(block.get("hash"), 32, "EVM block hash")
        if canonical_hash != reference.block_hash:
            if effect:
                self.ledger.reorg_effect(event_id, reference)
            else:
                self.ledger.reorg_origin(event_id, reference)
            raise ValueError("recorded EVM block was replaced")

    def _check_bsv_origin(
        self, rpc: Rpc, policy: BsvConfirmationPolicy, event_id: bytes, *, effect: bool = False,
    ) -> None:
        state = self.ledger.state(event_id)
        if state is None:
            return
        origin = state.effect if effect else state.origin
        if origin is None or state.phase == "orphaned":
            return
        info = _object(rpc("getblockchaininfo"), "BSV chain")
        if (info.get("chain") != policy.rpc_chain
                or _data("0x" + rpc("getblockhash", 0), 32, "BSV genesis hash")[::-1] != policy.genesis_hash):
            raise ValueError("unexpected BSV chain during reorg check")
        height = info.get("blocks")
        if type(height) is not int or height < 0:
            raise ValueError("invalid BSV tip height")
        active = (None if height < origin.height
                  else _data("0x" + rpc("getblockhash", origin.height), 32, "BSV block hash")[::-1])
        if active != origin.block_hash:
            if effect:
                self.ledger.reorg_effect(event_id, origin)
            else:
                self.ledger.reorg_origin(event_id, origin)
            raise ValueError("recorded BSV block was replaced")

    def authorize_mint(
        self, plan: MintPlan, load_mint_state: Callable[[], RecoveredMintState], sign_digest: DigestSigner,
    ) -> Transaction:
        """Consume only a verified finalized deposit against the current anchored state.

        The state loader verifies mint ancestry and unspent vout zero in the
        confirmed chain view. A pending mempool spend does not replace that
        confirmed state and can be recovered by retrying the identical plan.
        The signer must be idempotent by digest if a crash lost its response.
        """
        if plan.policy != self.mint_policy:
            raise ValueError("mint plan does not belong to this bridge")
        event_id = plan.deposit.position.event_id()

        def require_current_state():
            current = load_mint_state()
            if current.paused or current.transaction != plan.prior or current.events != plan.events:
                raise ValueError("current confirmed mint state does not match the plan")

        def observe(position: DepositPosition) -> Deposit:
            evidence = read_finalized_deposit(self.evm_rpc, self.reserve_scope,
                                              position.transaction_hash, position.log_ordinal)
            deposit = Deposit(
                DepositPosition(evidence.scope.chain_id, evidence.scope.reserve_domain, evidence.scope.vault,
                                evidence.tx_hash, evidence.receipt_log_ordinal),
                evidence.source_asset, evidence.scope.bsv_network, evidence.scope.asset_id,
                evidence.quantity, evidence.fee, evidence.owner,
            )
            self.ledger.observe_deposit(deposit, ChainReference(
                evidence.tx_hash, evidence.receipt_log_ordinal, evidence.block_hash, evidence.block_number,
            ), finalized=True)
            return deposit

        def sign(digest):
            require_current_state()
            self.ledger.authorize_mint(event_id, digest, plan.transaction.inputs[0].outpoint(),
                                       transaction=plan.transaction)
            cached = self.ledger.authorization_signature(event_id, digest)
            if cached is not None:
                _verify_bsv_signature(self.mint_policy.attestor, digest, cached)
                return cached
            signature = sign_digest(digest)
            _verify_bsv_signature(self.mint_policy.attestor, digest, signature)
            self._check_evm_origin(event_id)
            return self.ledger.record_authorization_signature(event_id, digest, signature)

        with _exclusive_signature_cache(self.ledger.path):
            self._check_evm_origin(event_id)
            require_current_state()
            tx = authorize_mint(plan, observe, sign)
            self._check_evm_origin(event_id)
            require_current_state()
            return tx

    def recover_mint(
        self, event_id: bytes, load_mint_state: Callable[[], RecoveredMintState], sign_digest: DigestSigner,
    ) -> Transaction:
        """Rebuild the identical signed mint from its persisted draft and confirmed state."""
        self._check_evm_origin(event_id)
        saved = self.ledger.mint_authorization_draft(event_id)
        current = load_mint_state()
        tx = saved.transaction
        if (current.paused or tx.inputs[0].txid != current.transaction.txid_wire()
                or tx.inputs[0].outpoint() != saved.state_outpoint):
            raise ValueError("current confirmed mint state does not match the saved authorization")
        change = tx.outputs[3] if len(tx.outputs) == 4 else None
        plan = prepare_mint(self.mint_policy, current.transaction, current.events, saved.deposit, tx.inputs[1],
                            change=change)
        prior = current.transaction.outputs[0]
        if plan.transaction != tx or hash256(preimage_all(tx, 0, prior.value, prior.script)) != saved.digest:
            raise ValueError("saved mint draft disagrees with its authorization digest")
        return self.authorize_mint(plan, load_mint_state, sign_digest)

    def record_mint(
        self, bsv_rpc: Rpc, bsv_policy: BsvConfirmationPolicy, reference: ChainReference,
        predecessor: RecoveredMintState,
    ) -> bytes:
        """Verify an independent node's confirmed mint against its recovered predecessor."""
        if reference.position != 1 or self.mint_policy.asset.network != bsv_policy.network:
            raise ValueError("mint chain reference does not identify the designated output")
        inclusion = BurnReference(reference.txid, reference.position, reference.block_hash, reference.height)
        require_canonical_burn_block(bsv_rpc, bsv_policy, inclusion)
        block = _object(bsv_rpc("getblock", reference.block_hash[::-1].hex(), 1), "BSV mint block")
        txid = reference.txid[::-1].hex()
        txids = block.get("tx")
        if (block.get("height") != reference.height or block.get("hash") != reference.block_hash[::-1].hex()
                or not isinstance(txids, list) or txid not in txids):
            raise ValueError("mint transaction is missing from its adopted block")
        raw = bsv_rpc("getrawtransaction", txid, False)
        if not isinstance(raw, str):
            raise ValueError("missing raw mint transaction")
        tx = Transaction.parse(bytes.fromhex(raw))
        if tx.txid_wire() != reference.txid:
            raise ValueError("mint bytes disagree with the adopted transaction ID")
        if predecessor.paused or len(tx.inputs) != 2 or len(tx.outputs) not in (3, 4):
            raise ValueError("mint effect does not extend a valid mint state")
        deposit = read_deposit(tx)
        change = tx.outputs[3] if len(tx.outputs) == 4 else None
        plan = prepare_mint(self.mint_policy, predecessor.transaction, predecessor.events,
                            deposit, tx.inputs[1], change=change)
        if tx.with_script(0, b"") != plan.transaction:
            raise ValueError("confirmed BSV transaction does not reproduce the expected mint")
        event_id = deposit.position.event_id()
        self._check_bsv_origin(bsv_rpc, bsv_policy, event_id, effect=True)
        require_canonical_burn_block(bsv_rpc, bsv_policy, inclusion)
        prior_output = predecessor.transaction.outputs[0]
        digest = hash256(preimage_all(tx, 0, prior_output.value, prior_output.script))
        self.ledger.note_confirmed_mint_spend(tx.inputs[0].outpoint(), event_id, digest)
        self.ledger.observe_mint(event_id, reference, deposit.net_quantity, deposit.owner, finalized=True)
        return event_id

    def authorize_release(
        self, bsv_rpc: Rpc, bsv_policy: BsvConfirmationPolicy, reference: BurnReference,
        lineage: ConfirmedLineage, sign_digest: DigestSigner,
    ) -> ReleaseAuthorization | Settlement:
        if lineage.mint_policy != self.mint_policy:
            raise ValueError("burn lineage does not belong to this bridge")
        asset = self.mint_policy.asset
        event_id = burn_event_id(asset.network, reference)
        self._check_bsv_origin(bsv_rpc, bsv_policy, event_id)
        self._check_evm_origin(event_id, effect=True)

        def provenance(burn: CanonicalBurn, burn_asset) -> bool:
            if burn_asset != asset or lineage.burn(reference.txid, reference.vout) != burn.receipt:
                return False
            actual = burn.reference
            self.ledger.observe_burn(burn.receipt, ChainReference(
                actual.txid, actual.vout, actual.block_hash, actual.block_height,
            ), finalized=True)
            return True

        def sign(digest):
            self.ledger.authorize(event_id, digest)
            cached = self.ledger.authorization_signature(event_id, digest)
            return cached if cached is not None else sign_digest(digest)

        with _exclusive_signature_cache(self.ledger.path):
            try:
                result = authorize_release(bsv_rpc, self.evm_rpc, bsv_policy, self.reserve_scope, asset, reference,
                                           verify_provenance=provenance, sign_digest=sign)
            except ValueError:
                # Preserve the adapter's diagnostic for temporary RPC errors.
                # A provably replaced block instead records the corresponding hold.
                self._check_bsv_origin(bsv_rpc, bsv_policy, event_id)
                raise
            if isinstance(result, ReleaseAuthorization):
                # The adapter has verified the current signer and canonical low-S signature.
                self.ledger.record_authorization_signature(event_id, result.digest, result.signature)
            else:
                self._check_settlement_digest(event_id, result.digest)
            return result

    def _check_settlement_digest(self, event_id: bytes, digest: bytes) -> None:
        state = self.ledger.state(event_id)
        if state is not None and state.authorization not in (None, digest):
            self.ledger.hold("reserve settlement disagrees with recorded authorization", digest, event_id=event_id)
            raise ValueError("reserve settlement digest does not match the recorded claim")

    def record_release(self, reference: ChainReference, burn_reference: BurnReference) -> EventState:
        """Ingest the configured reserve's actual release log and settlement state."""
        rpc, scope = self.evm_rpc, self.reserve_scope
        event_id = burn_event_id(scope.bsv_network, burn_reference)
        self._check_evm_origin(event_id, effect=True)
        if _quantity(rpc("eth_chainId"), "RPC chain ID") != scope.chain_id:
            raise ValueError("unexpected EVM chain for release receipt")
        receipt = _object(rpc("eth_getTransactionReceipt", "0x" + reference.txid.hex()), "release receipt")
        block = _object(rpc("eth_getBlockByNumber", hex(reference.height), False), "release block")
        tx_index = _quantity(receipt.get("transactionIndex"), "release transaction index")
        txids = block.get("transactions")
        if (_quantity(receipt.get("status"), "release receipt status") != 1
                or _data(receipt.get("transactionHash"), 32, "release transaction hash") != reference.txid
                or _data(receipt.get("blockHash"), 32, "release block hash") != reference.block_hash
                or _quantity(receipt.get("blockNumber"), "release block number") != reference.height
                or _data(block.get("hash"), 32, "canonical release block hash") != reference.block_hash
                or _quantity(block.get("number"), "canonical release block number") != reference.height
                or not isinstance(txids, list) or tx_index >= len(txids)
                or _data(txids[tx_index], 32, "canonical release transaction hash") != reference.txid):
            raise ValueError("release receipt is not canonical")
        logs = receipt.get("logs")
        if not isinstance(logs, list) or not 0 <= reference.position < len(logs):
            raise ValueError("release log position is outside the receipt")
        log = _object(logs[reference.position], "release log")
        first_index = _quantity(_object(logs[0], "first receipt log").get("logIndex"), "first release log index")
        if (log.get("removed", False) is not False
                or _quantity(log.get("logIndex"), "release log index") != first_index + reference.position
                or _data(log.get("transactionHash"), 32, "log transaction hash") != reference.txid
                or _data(log.get("blockHash"), 32, "log block hash") != reference.block_hash
                or _quantity(log.get("blockNumber"), "log block number") != reference.height
                or _quantity(log.get("transactionIndex"), "log transaction index") != tx_index
                or _data(log.get("address"), 20, "release emitter") != scope.vault):
            raise ValueError("release log does not belong to the configured reserve and receipt")
        topics = log.get("topics")
        if not isinstance(topics, list) or len(topics) != 4:
            raise ValueError("malformed release topics")
        topic, burn_id, burn_txid, recipient_word = (
            _data(item, 32, "release topic") for item in topics
        )
        payload = _data(log.get("data"), 128, "release parameters")
        vout, quantity, fee = (int.from_bytes(payload[i:i + 32], "big") for i in (0, 32, 64))
        digest = payload[96:128]
        if (topic != _RELEASE_TOPIC or burn_id != event_id or burn_txid != burn_reference.txid
                or vout != burn_reference.vout or any(recipient_word[:12]) or not any(recipient_word[12:])):
            raise ValueError("release log identifies another redemption")
        settlement = read_settlement(rpc, scope, burn_reference)
        if settlement is None or (settlement.burn_id, settlement.digest) != (burn_id, digest):
            raise ValueError("reserve contract has not settled this exact release")
        self._check_settlement_digest(event_id, digest)
        finalized = _object(rpc("eth_getBlockByNumber", "finalized", False), "finalized EVM block")
        final_height = _quantity(finalized.get("number"), "finalized EVM block number")
        final_hash = _data(finalized.get("hash"), 32, "finalized EVM block hash")
        confirmed = (settlement.finalized and reference.height <= final_height
                     and (reference.height != final_height or reference.block_hash == final_hash))
        canonical = _object(rpc("eth_getBlockByNumber", hex(reference.height), False), "release block")
        if (_quantity(canonical.get("number"), "canonical release block number") != reference.height
                or _data(canonical.get("hash"), 32, "canonical release block hash") != reference.block_hash):
            self.ledger.reorg_effect(event_id, reference)
            raise ValueError("release block changed while reading settlement")
        self.ledger.observe_release(event_id, reference, quantity, fee, recipient_word[12:], finalized=confirmed)
        return self.ledger.state(event_id)

    def pause(self, reason: str, evidence: bytes) -> None:
        self.ledger.hold(reason, evidence)

    def recheck_mint_effect(self, bsv_rpc: Rpc, policy: BsvConfirmationPolicy, event_id: bytes) -> None:
        state = self.ledger.state(event_id)
        if state is not None and state.lane != "mint":
            raise ValueError("event is not a mint")
        self._check_bsv_origin(bsv_rpc, policy, event_id, effect=True)

    def reconcile(self, *, source_balance: int, live_supply: int, frozen_supply: int):
        return self.ledger.reconcile(source_balance=source_balance, live_supply=live_supply, frozen_supply=frozen_supply)

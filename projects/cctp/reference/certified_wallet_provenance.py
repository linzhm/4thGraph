"""Authenticate wallet token creation under a configured continuity verifier.

Use a deploying party's trusted independently validating Bitcoin SV node.
Locator hints can come from an indexer, but the node validates their actual
block membership and transaction bytes. Portable Merkle evidence and lookup
of the output's known spend state remain separate wallet checks.
"""

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import TYPE_CHECKING

from projects.cctp.evm.bsv_burn_evidence import (
    BsvConfirmationPolicy, BsvNodeSnapshot, BsvTransactionLocation, read_bsv_raw_transaction,
)
from projects.cctp.evm.reserve_rpc import Rpc
from shared.transaction import Input, Transaction, blob, hash256
from statement import fixed, uint
from transaction_relation import TokenState
from wallet_receipt import BlockInclusion, SpendStatus, WalletReceipt

if TYPE_CHECKING:
    from continuity_verifier import ContinuityVerifier


class CertifiedWalletError(ValueError):
    """The transaction or designated output does not carry certified token creation."""


@dataclass(frozen=True)
class CertifiedCreation:
    operation: str
    txid_wire: bytes
    vout: int
    state: TokenState
    location: BsvTransactionLocation
    verifier_outpoint: bytes
    verifier_hash: bytes
    context: bytes
    proof_digest: bytes


@dataclass(frozen=True)
class SpendablePayment:
    """A live UTXO observation plus evidence of historical certified creation."""
    creation: CertifiedCreation
    receipt: WalletReceipt
    inclusion: BlockInclusion
    tip_height: int
    tip_hash: bytes


@dataclass(frozen=True)
class CertifiedWalletProvenance:
    verifier: "ContinuityVerifier"
    bsv_rpc: Rpc
    confirmation_policy: BsvConfirmationPolicy
    locate: Callable[[bytes], BsvTransactionLocation | None]

    def __post_init__(self):
        from continuity_verifier import ContinuityVerifier

        verifier = self.verifier
        if not isinstance(verifier, ContinuityVerifier) or not verifier.certified_mints:
            raise CertifiedWalletError("wallet requires a certified continuity mint policy")
        if self.confirmation_policy.network != verifier.asset.network:
            raise CertifiedWalletError("certified wallet verification network mismatch")
        if sha256(blob(verifier.lock)).digest() != verifier.mint_policy.certified_verifier_hash:
            raise CertifiedWalletError("wallet verifier does not match the certified mint policy")

    def valid_creation(self, tx: Transaction, vout: int) -> bool:
        """Boolean adapter for verify_payment's authenticated creation callback."""
        try:
            self.check_creation(tx, vout)
        except ValueError:
            return False
        return True

    def check_creation(self, tx: Transaction, vout: int) -> CertifiedCreation:
        return self._check_creation(tx, vout)

    def _check_creation(self, tx: Transaction, vout: int, snapshot: BsvNodeSnapshot | None = None) -> CertifiedCreation:
        verifier = self.verifier
        if type(vout) is not int or not 0 <= vout < len(tx.outputs):
            raise CertifiedWalletError("invalid designated wallet vout")
        kind, verifier_index = verifier._layout(tx)
        payment_slots = {
            "mint": (1,), "transfer": (0, 1), "single": (0,), "admin": (0,),
            "burn": (1,) if verifier.burn_profile(tx) == 1 else (),
            "capacity": range(len(tx.outputs) - 1),
        }
        if vout not in payment_slots.get(kind, ()):
            raise CertifiedWalletError("designated vout is not a certified token output")
        state = verifier.policy.parse(tx.outputs[vout].script)
        if state is None or state.asset_id != verifier.asset.asset_id():
            raise CertifiedWalletError("wrong designated wallet asset or token lock")
        if not 0 <= verifier_index < len(tx.inputs):
            raise CertifiedWalletError("missing executing verifier input")
        server = self.bsv_rpc("getnetworkinfo")
        subversion = server.get("subversion") if isinstance(server, dict) else None
        if not isinstance(subversion, str) or not subversion.startswith("/Bitcoin SV:"):
            raise CertifiedWalletError("certified wallet requires an independent Bitcoin SV full node RPC")
        if snapshot is None:
            snapshot = BsvNodeSnapshot(self.bsv_rpc, self.confirmation_policy)

        def location_of(txid):
            location = self.locate(txid)
            if not isinstance(location, BsvTransactionLocation):
                raise CertifiedWalletError("missing confirmed BSV wallet transaction location")
            return location

        loaded = {}

        def confirmed_at(txid, location):
            occurrence = snapshot.position(txid, location)
            if txid not in loaded:
                loaded[txid] = read_bsv_raw_transaction(self.bsv_rpc, txid)
            return loaded[txid], occurrence

        txid_wire = tx.txid_wire()
        location = location_of(txid_wire)
        confirmed, position = confirmed_at(txid_wire, location)
        if confirmed != tx:
            raise CertifiedWalletError("wallet transaction bytes differ from the adopted chain")

        def prevout(item: Input, consumer):
            parent, occurrence = confirmed_at(item.txid, location_of(item.txid))
            if occurrence >= consumer or not 0 <= item.vout < len(parent.outputs):
                raise CertifiedWalletError("BSV predecessor does not precede its spend or has an invalid vout")
            return parent, occurrence

        def executing_funding(transaction, occurrence, index):
            if not 0 <= index < len(transaction.inputs):
                raise CertifiedWalletError("missing actual verifier input")
            funding, _ = prevout(transaction.inputs[index], occurrence)
            verifier.policy.selected_verifier(transaction, funding.serialize(), index=index)
            return funding

        def previous_proof(parent, occurrence):
            return executing_funding(parent, occurrence, verifier.verifier_input_index(parent))

        funding = executing_funding(tx, position, verifier_index)
        candidate_receipt, _ = verifier.context(tx, funding)
        suffix = None
        if kind in ("mint", "admin"):
            parent, occurrence = prevout(tx.inputs[0], position)
            prior_funding = (previous_proof(parent, occurrence)
                             if kind == "admin" or candidate_receipt.parents else None)
            supporting = () if prior_funding is None else (prior_funding,)
            parents = (parent,)
            if kind == "mint":
                receipt, context = verifier.validate_mint(tx, funding, parent, prior_funding)
                mode = 3 + len(receipt.parents)
            else:
                receipt, context = verifier.validate_admin(tx, funding, parent, prior_funding)
                mode = 5
                kind = "freeze" if state.frozen else "unfreeze"
        elif kind == "capacity":
            companion, _ = prevout(tx.inputs[1], position)
            groups = {}
            for item in tx.inputs[2:]:
                if item.txid not in groups:
                    parent, occurrence = prevout(item, position)
                    groups[item.txid] = (previous_proof(parent, occurrence), parent)
            pairs = tuple(groups.values())
            receipt, context = verifier.validate_capacity(tx, funding, companion, pairs)
            suffix = verifier.capacity_witness_suffix(tx, funding, companion, pairs)
        else:
            candidates = tuple(prevout(item, position) for item in tx.inputs[1:])
            parents = tuple(parent for parent, _ in candidates)
            supporting = tuple(previous_proof(parent, occurrence) for parent, occurrence in candidates)
            if kind == "burn":
                receipt, context, _ = verifier.validate_burn(tx, funding, parents, supporting)
                mode = verifier.burn_mode(tx)
                kind = "burn-change"
            else:
                receipt, context = verifier.validate(tx, funding, parents, supporting)
                mode = verifier.transfer_mode(tx)

        expected_context = hash256(verifier.context_preimage(tx, funding, verifier_index))
        if suffix is None:
            suffix = verifier.transaction_material(tx, funding, parents, supporting, count=mode,
                                                   verifier_index=verifier_index)
        if context != expected_context:
            raise CertifiedWalletError("certified witness does not attest the adopted wallet transaction context")
        try:
            verifier.confirmed_witness_padding(tx, verifier_index, suffix)
        except ValueError as error:
            raise CertifiedWalletError("certified witness does not attest the adopted wallet transaction context") from error
        snapshot.check_active()
        verifier_hash = sha256(blob(funding.outputs[0].script)).digest()
        return CertifiedCreation(
            kind, txid_wire, vout, state, location, tx.inputs[verifier_index].outpoint(),
            verifier_hash, context, receipt.digest(verifier.asset.asset_id(), verifier.key_digest, context),
        )

    def check_spendable(self, tx: Transaction, vout: int, *, expected_owner: bytes, expected_quantity: int,
                        inclusion: BlockInclusion | None = None) -> SpendablePayment:
        """Match the order and check spendability at this node's observed tip and mempool.

        The wallet configures the asset, verifier and confirmation policy before
        receiving the payment. Recheck current availability before a later spend.
        The outpoint is the idempotency key for a wallet's accounting ledger.
        """
        fixed(expected_owner, 33)
        uint(expected_quantity, 8)
        if expected_quantity == 0:
            raise CertifiedWalletError("expected a positive payment quantity")
        snapshot = BsvNodeSnapshot(self.bsv_rpc, self.confirmation_policy)
        creation = self._check_creation(tx, vout, snapshot)
        state = creation.state
        if state.owner != expected_owner or state.quantity != expected_quantity:
            raise CertifiedWalletError("certified output does not match the expected owner and quantity")
        if state.frozen:
            raise CertifiedWalletError("certified payment output is frozen")

        location = creation.location
        # The creation check authenticated and cached the adopted block's ordered
        # txid -> index mapping for this same snapshot.
        _, positions = snapshot.blocks[location.height]
        index = positions[creation.txid_wire]
        if inclusion is None:
            header = self.bsv_rpc("getblockheader", location.block_hash[::-1].hex(), False)
            inclusion = BlockInclusion.from_block(bytes.fromhex(header), location.height, tuple(positions), index)
        if (inclusion.height != location.height or inclusion.block_hash() != location.block_hash
                or inclusion.index != index or inclusion.leaf_count != len(positions)):
            raise CertifiedWalletError("Merkle inclusion differs from the adopted transaction position")
        inclusion.verify(creation.txid_wire)

        # An output created in a confirmed block can already be spent in the
        # node's mempool. The chain-only gettxout view would still return it.
        coin = self.bsv_rpc("gettxout", tx.txid(), vout, True)
        confirmations = snapshot.tip - location.height + 1
        if not isinstance(coin, dict):
            raise CertifiedWalletError("output is spent, conflicted or unavailable at the wallet node")
        if (coin.get("bestblock") != snapshot.tip_hash[::-1].hex()
                or type(coin.get("confirmations")) is not int or coin["confirmations"] != confirmations):
            raise CertifiedWalletError("UTXO observation differs from the wallet chain snapshot")
        script = coin.get("scriptPubKey")
        try:
            value = Decimal(str(coin.get("value")))
        except InvalidOperation as exc:
            raise CertifiedWalletError("invalid UTXO amount") from exc
        actual = tx.outputs[vout]
        if (not value.is_finite() or value != Decimal(actual.value).scaleb(-8)
                or not isinstance(script, dict) or script.get("hex") != actual.script.hex()):
            raise CertifiedWalletError("unspent output differs from the certified payment")
        snapshot.check_active()
        outpoint = Input(creation.txid_wire, vout).outpoint()
        receipt = WalletReceipt(outpoint, state.quantity, state.owner, state.frozen, confirmations, SpendStatus.UNSPENT)
        return SpendablePayment(creation, receipt, inclusion, snapshot.tip, snapshot.tip_hash)

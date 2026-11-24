"""Read one canonical confirmed BSV burn and keep provenance validation separate."""

from dataclasses import dataclass
import re

from burn_receipt import BurnReceipt, read_burn
from shared.transaction import Transaction
from statement import AssetDescriptor, fixed, uint

from projects.cctp.evm.reserve_rpc import Rpc


class BurnEvidenceError(ValueError):
    """BSV has not provided acceptable evidence for the referenced burn."""


@dataclass(frozen=True)
class BsvConfirmationPolicy:
    network: int
    rpc_chain: str
    genesis_hash: bytes
    minimum_confirmations: int

    def __post_init__(self):
        uint(self.network, 4)
        fixed(self.genesis_hash, 32)
        uint(self.minimum_confirmations, 4)
        if (not isinstance(self.rpc_chain, str) or not self.rpc_chain
                or not any(self.genesis_hash) or self.minimum_confirmations == 0):
            raise ValueError("incomplete BSV confirmation policy")


@dataclass(frozen=True)
class BurnReference:
    """BSV txid and block hash in wire order, with the precise receipt vout."""

    txid: bytes
    vout: int
    block_hash: bytes
    block_height: int

    def __post_init__(self):
        fixed(self.txid, 32)
        fixed(self.block_hash, 32)
        uint(self.vout, 4)
        uint(self.block_height, 4)
        if not any(self.txid) or not any(self.block_hash):
            raise ValueError("missing BSV transaction or block hash")


@dataclass(frozen=True)
class CanonicalBurn:
    reference: BurnReference
    transaction: Transaction
    receipt: BurnReceipt
    confirmations: int


def _hash_wire(value: object) -> bytes:
    if not isinstance(value, str) or re.fullmatch("[0-9a-fA-F]{64}", value) is None:
        raise BurnEvidenceError("invalid BSV RPC hash")
    return bytes.fromhex(value)[::-1]


def _analyze_tip(rpc: Rpc, policy: BsvConfirmationPolicy) -> tuple[int, bytes]:
    chain = rpc("getblockchaininfo")
    if not isinstance(chain, dict) or chain.get("chain") != policy.rpc_chain:
        raise BurnEvidenceError("unexpected BSV RPC chain")
    if _hash_wire(rpc("getblockhash", 0)) != policy.genesis_hash:
        raise BurnEvidenceError("unexpected BSV genesis hash")
    tip = chain.get("blocks")
    if type(tip) is not int or tip < 0:
        raise BurnEvidenceError("invalid BSV chain height")
    return tip, _hash_wire(chain.get("bestblockhash"))


def require_canonical_burn_block(rpc: Rpc, policy: BsvConfirmationPolicy, reference: BurnReference) -> int:
    """Recheck the referenced active-chain block, including on replay and after signing."""
    tip, tip_hash = _analyze_tip(rpc, policy)
    if tip < reference.block_height:
        raise BurnEvidenceError("burn block is above the active BSV tip")
    if _hash_wire(rpc("getblockhash", reference.block_height)) != reference.block_hash:
        raise BurnEvidenceError("burn block changed on the active BSV chain")
    confirmations = tip - reference.block_height + 1
    if confirmations < policy.minimum_confirmations:
        raise BurnEvidenceError("burn does not meet the BSV confirmation policy")
    if _hash_wire(rpc("getblockhash", tip)) != tip_hash:
        raise BurnEvidenceError("BSV tip changed during confirmation check")
    return confirmations


def read_confirmed_burn(
    rpc: Rpc, policy: BsvConfirmationPolicy, reference: BurnReference, asset: AssetDescriptor,
) -> CanonicalBurn:
    """Validate the node's transaction and containing block evidence before provenance."""
    if asset.network != policy.network:
        raise BurnEvidenceError("BSV asset network and confirmation policy mismatch")
    confirmations = require_canonical_burn_block(rpc, policy, reference)
    block_hash = reference.block_hash[::-1].hex()
    block = rpc("getblock", block_hash, 1)
    if (not isinstance(block, dict) or _hash_wire(block.get("hash")) != reference.block_hash
            or type(block.get("height")) is not int or block["height"] != reference.block_height):
        raise BurnEvidenceError("unexpected BSV burn block")
    txid = reference.txid[::-1].hex()
    transactions = block.get("tx")
    if not isinstance(transactions, list) or txid not in transactions:
        raise BurnEvidenceError("burn transaction absent from the BSV block")
    # Block membership already supplied confirmation evidence. Fetch the raw
    # hex without verbose Script disassembly for multi-megabyte burn inputs.
    raw = rpc("getrawtransaction", txid, False)
    if not isinstance(raw, str) or re.fullmatch("(?:[0-9a-fA-F]{2})+", raw) is None:
        raise BurnEvidenceError("missing canonical BSV transaction bytes")
    try:
        transaction = Transaction.parse(bytes.fromhex(raw))
        if transaction.txid_wire() != reference.txid:
            raise ValueError("BSV transaction bytes have a different hash")
        receipt = read_burn(transaction, reference.vout, asset)
    except ValueError as exc:
        raise BurnEvidenceError(str(exc)) from exc
    return CanonicalBurn(reference, transaction, receipt, confirmations)

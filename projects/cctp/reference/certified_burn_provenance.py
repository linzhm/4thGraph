"""Release evidence for the configured same-key continuity verifier.

The BSV RPC is the independent, trusted consensus validator. A locator can
come from an indexer, but its block hints and transaction ancestry are checked
against the node. This adapter does not treat an explorer response or raw
transactions alone as validation of Script or of recursive proofs.
"""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING

from burn_receipt import BurnReceipt, read_burn
from mint import MintPolicy
from projects.cctp.evm.bsv_burn_evidence import (
    BsvConfirmationPolicy, BsvNodeSnapshot, BsvTransactionLocation, BurnEvidenceError,
    BurnReference, CanonicalBurn, read_bsv_raw_transaction,
)
from projects.cctp.evm.reserve_rpc import Rpc
from shared.transaction import Input, blob, hash256

if TYPE_CHECKING:
    from continuity_verifier import ContinuityVerifier


@dataclass(frozen=True)
class CertifiedBurn:
    reference: BurnReference
    receipt: BurnReceipt
    verifier_outpoint: bytes
    verifier_hash: bytes
    context: bytes
    proof_digest: bytes


@dataclass(frozen=True)
class CertifiedBurnProvenance:
    """Authenticate a confirmed burn using one preconfigured certified profile."""

    verifier: "ContinuityVerifier"
    locate: Callable[[bytes], BsvTransactionLocation | None]

    def __post_init__(self):
        from continuity_verifier import ContinuityVerifier

        if not isinstance(self.verifier, ContinuityVerifier) or not (
            self.verifier.certified_mints and getattr(self.verifier, "certified_burns", False)
        ):
            raise ValueError("release requires a certified continuity burn verifier")
        if sha256(blob(self.verifier.lock)).digest() != self.mint_policy.certified_verifier_hash:
            raise ValueError("configured continuity verifier does not match the certified mint policy")

    @property
    def mint_policy(self) -> MintPolicy:
        return self.verifier.mint_policy

    def verify(self, burn: CanonicalBurn, rpc: Rpc, policy: BsvConfirmationPolicy) -> CertifiedBurn:
        ref, tx = burn.reference, burn.transaction
        verifier = self.verifier
        if policy.network != self.mint_policy.asset.network:
            raise BurnEvidenceError("certified burn verification network mismatch")
        if ref.vout != 0 or tx.txid_wire() != ref.txid:
            raise BurnEvidenceError("wrong certified burn transaction or vout")
        if read_burn(tx, 0, verifier.asset) != burn.receipt:
            raise BurnEvidenceError("canonical burn receipt differs from confirmed evidence")
        if len(tx.inputs) not in (2, 3) or len(tx.outputs) not in (2, 3):
            raise BurnEvidenceError("unexpected certified burn input or output layout")

        server = rpc("getnetworkinfo")
        subversion = server.get("subversion") if isinstance(server, dict) else None
        if not isinstance(subversion, str) or not subversion.startswith("/Bitcoin SV:"):
            raise BurnEvidenceError("certified release requires an independent Bitcoin SV full node RPC")
        snapshot = BsvNodeSnapshot(rpc, policy)
        position = snapshot.position(ref.txid, BsvTransactionLocation(ref.block_hash, ref.block_height))
        loaded = {}

        def prevout(txin: Input, consumer_position):
            if txin.txid not in loaded:
                location = self.locate(txin.txid)
                if not isinstance(location, BsvTransactionLocation):
                    raise BurnEvidenceError("missing confirmed BSV predecessor location")
                occurrence = snapshot.position(txin.txid, location)
                loaded[txin.txid] = read_bsv_raw_transaction(rpc, txin.txid), occurrence
            transaction, occurrence = loaded[txin.txid]
            if occurrence >= consumer_position or not 0 <= txin.vout < len(transaction.outputs):
                raise BurnEvidenceError("BSV predecessor does not precede its spend or has an invalid vout")
            return transaction, occurrence

        funding, _ = prevout(tx.inputs[0], position)
        verifier.policy.selected_verifier(tx, funding.serialize(), index=0)
        verifier_hash = sha256(blob(funding.outputs[0].script)).digest()
        if verifier_hash != self.mint_policy.certified_verifier_hash:
            raise BurnEvidenceError("wrong executing certified burn verifier")
        parents, supporting = [], []
        for txin in tx.inputs[1:]:
            parent, occurrence = prevout(txin, position)
            prior_index = verifier.verifier_input_index(parent)
            if not 0 <= prior_index < len(parent.inputs):
                raise BurnEvidenceError("missing actual certified predecessor verifier input")
            prior_funding, _ = prevout(parent.inputs[prior_index], occurrence)
            verifier.policy.selected_verifier(parent, prior_funding.serialize(), index=prior_index)
            parents.append(parent)
            supporting.append(prior_funding)
        parents, supporting = tuple(parents), tuple(supporting)
        receipt, context, actual_burn = verifier.validate_burn(tx, funding, parents, supporting)
        expected_context = hash256(verifier.context_preimage(tx, funding, 0))
        material = verifier.burn_material(tx, funding, parents, supporting)
        witness = tx.inputs[0].script
        if (actual_burn != burn.receipt or context != expected_context or len(witness) <= len(material)
                or not witness.endswith(material)):
            raise BurnEvidenceError("certified burn witness does not attest the exact confirmed transaction context")

        snapshot.check_active()
        proof_digest = receipt.digest(verifier.asset.asset_id(), verifier.key_digest, context)
        return CertifiedBurn(ref, actual_burn, tx.inputs[0].outpoint(), verifier_hash, context, proof_digest)

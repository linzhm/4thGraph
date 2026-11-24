"""Reference relation between signed parent bytes and a parent-binding statement.

This module derives and checks statement bytes. Script execution, proof
verification and chain inclusion are additional predicates outside the relation.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING

from operational_token import TokenPolicy
from shared.transaction import (
    CHRONICLE, FORKID, SIGHASH_ALL, Input, Output, Transaction, blob, compact, hash256, preimage_all,
)
from statement import fixed, uint
from transaction_relation import TokenState
from transfer import COMPACT_SCRIPTCODE

if TYPE_CHECKING:
    from continuity_verifier import ContinuityVerifier


PARENT_BINDING_DOMAIN = b"BSV/CCTP/parent-binding/v1\x00"
PARENT_BINDING_SIZE = len(PARENT_BINDING_DOMAIN) + 5 * 32 + 1 + 4
LEGACY_ALL = FORKID | SIGHASH_ALL
CHRONICLE_ALL = CHRONICLE | LEGACY_ALL


@dataclass(frozen=True)
class ParentBinding:
    asset_id: bytes
    verifier_script_field_hash: bytes
    sighash_type: int
    parent_txid_wire: bytes
    hash_outputs: bytes
    output_count: int
    continuity_digest: bytes

    def __post_init__(self):
        for field in (
            self.asset_id, self.verifier_script_field_hash, self.parent_txid_wire,
            self.hash_outputs, self.continuity_digest,
        ):
            fixed(field, 32)
        if type(self.sighash_type) is not int or self.sighash_type not in (LEGACY_ALL, CHRONICLE_ALL):
            raise ValueError("expected a supported parent-binding SIGHASH_ALL type")
        uint(self.output_count, 4)
        if self.output_count == 0:
            raise ValueError("parent binding requires an output")

    def statement(self) -> bytes:
        return (
            PARENT_BINDING_DOMAIN + self.asset_id + self.verifier_script_field_hash
            + bytes([self.sighash_type]) + self.parent_txid_wire + self.hash_outputs
            + uint(self.output_count, 4) + self.continuity_digest
        )

    def digest(self) -> bytes:
        return hash256(self.statement())

    @classmethod
    def parse(cls, raw: bytes) -> "ParentBinding":
        fixed(raw, PARENT_BINDING_SIZE)
        if not raw.startswith(PARENT_BINDING_DOMAIN):
            raise ValueError("incorrect parent-binding domain")
        fields = raw[len(PARENT_BINDING_DOMAIN):]
        return cls(fields[:32], fields[32:64], fields[64], fields[65:97], fields[97:129],
                   int.from_bytes(fields[129:133], "little"), fields[133:])

    def verify_outputs(self, raw_outputs: bytes) -> tuple[Output, ...]:
        """Check and parse exactly the counted concatenation of serialized outputs."""
        if type(raw_outputs) is not bytes or hash256(raw_outputs) != self.hash_outputs:
            raise ValueError("output vector does not match parent hashOutputs")
        # Frame the vector with zero inputs and fixed outer fields to reuse
        # the canonical transaction output parser and exact consumption check.
        framed = bytes(5) + compact(self.output_count) + raw_outputs + bytes(4)
        return Transaction.parse(framed).outputs

    def verify_token_at(
        self, raw_outputs: bytes, outpoint: Input, policy: TokenPolicy, *, allow_frozen: bool = False,
    ) -> TokenState:
        """Check a child input against the vector and the configured token policy."""
        if (outpoint.txid != self.parent_txid_wire or type(outpoint.vout) is not int
                or not 0 <= outpoint.vout < self.output_count):
            raise ValueError("outpoint does not select this parent's output")
        if type(allow_frozen) is not bool:
            raise ValueError("expected an explicit boolean frozen-token policy")
        if policy.verifier_hashes() != (self.verifier_script_field_hash,):
            raise ValueError("token policy does not match the bound verifier script field")
        selected = self.verify_outputs(raw_outputs)[outpoint.vout]
        token = policy.parse(selected.script)
        if token is None or token.asset_id != self.asset_id or (token.frozen and not allow_frozen):
            raise ValueError("selected output is not an eligible token of the bound asset")
        return token


def derive_parent_binding(verifier: "ContinuityVerifier", parent_raw: bytes, funding_raw: bytes) -> ParentBinding:
    """Build the statement from actual serialized parent and verifier funding bytes.

    The selected verifier input must carry witness bytes. This reference
    derives the fixed v3 0x41 context from the actual prevout and funded amount.
    A dual-mode relation must recover the exact verifier branch from the actual
    canonical witness or authenticated receipt and reconstruct that sighash.
    Script execution or confirmation requires separate evidence.
    """
    if type(parent_raw) is not bytes or type(funding_raw) is not bytes:
        raise ValueError("expected raw parent and funding bytes")
    parent = Transaction.parse(parent_raw)
    funding = Transaction.parse(funding_raw)
    index = verifier.verifier_input_index(parent)
    if not 0 <= index < len(parent.inputs) or not parent.inputs[index].script:
        raise ValueError("missing witness for the parent verifier input")
    receipt, context = verifier.context(parent, funding)
    funded = funding.outputs[parent.inputs[index].vout]
    preimage = preimage_all(parent, index, funded.value, COMPACT_SCRIPTCODE)
    if context != hash256(preimage):
        raise ValueError("parent context does not use the fixed 0x41 verifier path")
    asset_id = verifier.asset.asset_id()
    continuity = receipt.digest(asset_id, verifier.key_digest, context)
    # The last 40 bytes of this compact ALL preimage are hashOutputs, locktime and sighash type.
    hash_outputs = preimage[-40:-8]
    return ParentBinding(
        asset_id, sha256(blob(funded.script)).digest(), LEGACY_ALL, hash256(parent_raw),
        hash_outputs, len(parent.outputs), continuity,
    )


def verify_parent_binding(
    verifier: "ContinuityVerifier", expected: ParentBinding, parent_raw: bytes, funding_raw: bytes,
) -> ParentBinding:
    """Recompute the whole reference relation and require the expected statement."""
    actual = derive_parent_binding(verifier, parent_raw, funding_raw)
    if actual != expected:
        raise ValueError("parent bytes and funding do not match the parent-binding statement")
    return actual

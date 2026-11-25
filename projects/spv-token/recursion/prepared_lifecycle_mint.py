"""Bind finalized reserve deposits to the executing lifecycle issuance spend."""

from dataclasses import dataclass

from bridge_ledger import ChainReference
from bridge_service import _exclusive_signature_cache, _verify_bsv_signature
from mint_events import Deposit, DepositPosition
from prepared_lifecycle import Action, Previous
from prepared_lifecycle_wire import ACTIVE, ISSUANCE, MINT, State
from evm.reserve_rpc import FinalizedDeposit, read_finalized_deposit


@dataclass(frozen=True)
class MintGrant:
    prior: Previous
    evidence: FinalizedDeposit
    deposit: Deposit
    action: Action

    @classmethod
    def prepare(cls, policy, prior, rpc, scope, position):
        asset = policy.asset
        if (scope.asset_id != asset.asset_id() or scope.bsv_network != asset.network
                or scope.reserve_domain != asset.reserve_domain or bytes(12) + scope.reserve_asset != asset.reserve_asset
                or (position.source_chain_id, position.reserve_domain, position.reserve_contract)
                   != (scope.chain_id, scope.reserve_domain, scope.vault)):
            raise ValueError("mint grant belongs to a different reserve or asset")
        evidence = read_finalized_deposit(rpc, scope, position.transaction_hash, position.log_ordinal)
        verified_position = DepositPosition(scope.chain_id, scope.reserve_domain, scope.vault, evidence.tx_hash,
                                            evidence.receipt_log_ordinal)
        if verified_position != position:
            raise ValueError("finalized deposit differs from requested source event")
        deposit = Deposit(position, evidence.source_asset, asset.network, asset.asset_id(), evidence.quantity,
                          evidence.fee, evidence.owner)
        previous = policy.state(prior)
        if previous.kind != ISSUANCE or evidence.vault_nonce != previous.nonce + 1:
            raise ValueError("deposit does not follow the authenticated reserve nonce")
        action = Action(MINT, (State(ISSUANCE, previous.units + deposit.net_quantity, evidence.vault_nonce),
                               State(ACTIVE, deposit.net_quantity, owner=deposit.owner)),
                        (policy.issuer,) * 2, event=position.event_id())
        return cls(prior, evidence, deposit, action)

    def authorize(self, policy, tx, companion, verifier, parents, rpc, ledger, state_unspent, sign):
        """Journal and sign the exact canonical mint, after rechecking both chains."""
        if parents[0] != self.prior or tx != policy.draft(companion, verifier, parents, self.action):
            raise ValueError("different issuance input, validator or canonical output vector")
        scope = self.evidence.scope
        if (ledger.asset != policy.asset or ledger.source_chain_id != scope.chain_id
                or ledger.reserve_contract != scope.vault or companion.outputs[0].script != policy.companion
                or verifier.outputs[0].script != policy.verifier):
            raise ValueError("incorrect mint scope or funding policy")
        outpoint = self.prior.input.outpoint()
        digest = policy.verifier_digest(tx, verifier)
        event = self.deposit.position.event_id()
        with _exclusive_signature_cache(ledger.path):
            repeated = self.prepare(policy, self.prior, rpc, scope, self.deposit.position)
            if (repeated.evidence.block_hash != self.evidence.block_hash or repeated.deposit != self.deposit
                    or repeated.action != self.action or state_unspent(outpoint) is not True):
                raise ValueError("mint deposit or issuance input changed before signing")
            ref = ChainReference(self.evidence.tx_hash, self.evidence.receipt_log_ordinal,
                                 self.evidence.block_hash, self.evidence.block_number)
            ledger.observe_deposit(self.deposit, ref, finalized=True)
            ledger.authorize_mint(event, digest, outpoint)
            signature = ledger.authorization_signature(event, digest)
            if signature is None:
                signature = sign(digest)
                _verify_bsv_signature(policy.issuer, digest, signature)
                signature = ledger.record_authorization_signature(event, digest, signature)
            return signature

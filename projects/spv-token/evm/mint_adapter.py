"""Connect the EVM deposit reader to the BSV mint authorization callback."""

from collections.abc import Callable

from mint_events import Deposit, DepositPosition
from evm.reserve_rpc import ReserveScope, Rpc, read_finalized_deposit


def finalized_deposit_reader(rpc: Rpc, scope: ReserveScope) -> Callable[[DepositPosition], Deposit | None]:
    """Trust the configured finalized RPC, then construct the canonical mint payload."""
    def observe(position: DepositPosition) -> Deposit | None:
        if (position.source_chain_id != scope.chain_id
                or position.reserve_domain != scope.reserve_domain
                or position.reserve_contract != scope.vault):
            return None
        evidence = read_finalized_deposit(rpc, scope, position.transaction_hash, position.log_ordinal)
        authenticated_position = DepositPosition(
            evidence.scope.chain_id, evidence.scope.reserve_domain, evidence.scope.vault,
            evidence.tx_hash, evidence.receipt_log_ordinal,
        )
        return Deposit(
            authenticated_position, evidence.source_asset, evidence.scope.bsv_network,
            evidence.scope.asset_id, evidence.quantity, evidence.fee, evidence.owner,
        )

    return observe

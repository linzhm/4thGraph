"""Reference relation for one recursive MIMO transfer step."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from shared.transaction import Transaction
from token_transfer import check_transfer_relation, read_token_state
from transfer import TransferStatement

PublicInputs = tuple[int, int]
ProofVerifier = Callable[[PublicInputs, bytes], bool]


@dataclass(frozen=True)
class PriorProof:
    verifier_parent: Transaction
    proof: bytes


@dataclass(frozen=True)
class RecursiveTransfer:
    statement: TransferStatement
    initial_supply: int
    shared_guard: bool = False

    def _is_issuance(self, transaction: Transaction) -> bool:
        return (
            len(transaction.inputs) == 1
            and transaction.inputs[0].outpoint() == self.statement.issuance_outpoint
        )

    def _check_issuance(self, transaction: Transaction) -> None:
        supply = 0
        for output in transaction.outputs:
            state = read_token_state(output.script, self.statement.authorized_lock, shared_guard=self.shared_guard)
            if state is not None:
                if state.issuance != self.statement.issuance_outpoint:
                    raise ValueError("wrong issuance output")
                supply += state.quantity
        if not 0 < self.initial_supply < 2**64 or supply != self.initial_supply:
            raise ValueError("issuance supply mismatch")

    def check(
        self, transaction: Transaction, parents: tuple[Transaction, ...],
        preceding: Mapping[bytes, PriorProof], verify_prior: ProofVerifier,
    ) -> PublicInputs:
        """Supply one verified statement per distinct non-issuance token parent."""
        if not parents or len(transaction.inputs) != len(parents):
            raise ValueError("missing input parent")
        checked_parents = set()
        authenticated = set()
        first_token_slot = 2 if self.shared_guard else 1
        for txin, parent in zip(transaction.inputs[first_token_slot:], parents[first_token_slot:], strict=True):
            parent_id = parent.txid_wire()
            if txin.txid != parent_id or not 0 <= txin.vout < len(parent.outputs):
                raise ValueError("input parent mismatch")
            state = read_token_state(
                parent.outputs[txin.vout].script, self.statement.authorized_lock, shared_guard=self.shared_guard,
            )
            if state is None:
                continue
            if parent_id not in checked_parents:
                if self._is_issuance(parent):
                    self._check_issuance(parent)
                else:
                    prior = preceding.get(parent_id)
                    if prior is None:
                        raise ValueError("missing parent transfer proof")
                    public = self.statement.public_inputs(parent, 0, prior.verifier_parent)
                    if not verify_prior(public, prior.proof):
                        raise ValueError("invalid parent transfer proof")
                checked_parents.add(parent_id)
            authenticated.add(txin.outpoint())
        check_transfer_relation(
            transaction, parents, self.statement.issuance_outpoint, self.statement.authorized_lock, authenticated,
            shared_guard=self.shared_guard,
        )
        return self.statement.public_inputs(transaction, 0, parents[0])

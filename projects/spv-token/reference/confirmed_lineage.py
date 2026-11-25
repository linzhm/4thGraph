"""Wallet and release provenance over a consensus-validated adopted BSV chain."""

from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property

from burn_receipt import BurnReceipt, read_burn
from mimo_verifier import MimoProfile
from mint import MintPolicy, recover_mint_state
from operational_token import FORKID_ALL, FORKID_SINGLE, TokenPolicy
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction, preimage_forkid
from statement import fixed, uint
from transaction_relation import TokenState
from verifier import VerificationKey

ConfirmedLoader = Callable[[bytes], bytes | None]
Outpoint = tuple[bytes, int]


@dataclass(frozen=True)
class ConfirmedLineage:
    """Trace recognized transitions from authentic issuance.

    The loader accepts wire-order transaction IDs. It must supply raw bytes
    from a coherent snapshot of the adopted chain at the required depth,
    verified by a consensus node or equivalent validation. A new query makes
    fresh loader calls so transaction removals after a reorg are visible.
    """

    mint_policy: MintPolicy
    token_policy: TokenPolicy
    profiles: tuple[tuple[MimoProfile, VerificationKey], ...]
    load_confirmed: ConfirmedLoader

    def __post_init__(self):
        if set(self._profile_locks) != set(self.token_policy.verifier_locks):
            raise ValueError("verified profiles do not match the approved token policy")

    @cached_property
    def _profile_locks(self) -> dict[bytes, MimoProfile]:
        result = {}
        for profile, key in self.profiles:
            if (profile.freeze_key != self.token_policy.freeze_key
                    or profile.guards != len(self.token_policy.verifier_locks)):
                raise ValueError("profile scope does not match the approved token policy")
            lock = profile.lock(self.mint_policy.asset, key)
            if lock in result:
                raise ValueError("duplicate verifier profile")
            result[lock] = profile
        return result

    def token(self, txid_wire: bytes, vout: int) -> TokenState:
        return _Walk(self).verify_token(fixed(txid_wire, 32), _vout(vout))

    def burn(self, txid_wire: bytes, vout: int) -> BurnReceipt:
        walk = _Walk(self)
        operation = walk.verify(fixed(txid_wire, 32))
        if operation.burn_vout != _vout(vout):
            raise ValueError("vout is not the authenticated burn receipt")
        return read_burn(walk.load(txid_wire), vout, self.mint_policy.asset)

    def valid_creation(self, transaction: Transaction, vout: int) -> bool:
        """Adapter for wallet_receipt.verify_payment."""
        try:
            self.token(transaction.txid_wire(), vout)
        except ValueError:
            return False
        return True


def _vout(value: int) -> int:
    uint(value, 4)
    return value


@dataclass(frozen=True)
class _Operation:
    tokens: dict[int, TokenState]
    parents: tuple[Outpoint, ...]
    burn_vout: int | None = None


class _Walk:
    def __init__(self, lineage: ConfirmedLineage):
        self.lineage = lineage
        self.transactions: dict[bytes, Transaction] = {}
        self.operations: dict[bytes, _Operation] = {}
        self.verified: set[bytes] = set()

    @property
    def mint_policy(self) -> MintPolicy:
        return self.lineage.mint_policy

    @property
    def token_policy(self) -> TokenPolicy:
        return self.lineage.token_policy

    def load(self, txid: bytes) -> Transaction:
        if txid not in self.transactions:
            raw = self.lineage.load_confirmed(txid)
            if raw is None:
                raise ValueError("lineage transaction is missing from the confirmed adopted chain")
            if type(raw) is not bytes:
                raise ValueError("lineage loader must return canonical transaction bytes")
            tx = Transaction.parse(raw)
            if tx.txid_wire() != txid:
                raise ValueError("lineage transaction bytes do not match the requested ID")
            self.transactions[txid] = tx
        return self.transactions[txid]

    def prevout(self, spend: Input) -> tuple[Transaction, Output]:
        parent = self.load(spend.txid)
        if not 0 <= spend.vout < len(parent.outputs):
            raise ValueError("lineage input points to a missing parent output")
        return parent, parent.outputs[spend.vout]

    def token_state(self, output: Output) -> TokenState | None:
        state = self.token_policy.parse(output.script)
        if state is not None and state.asset_id != self.mint_policy.asset.asset_id():
            raise ValueError("token is from a different asset")
        return state

    def active_state(self, output: Output) -> TokenState:
        state = self.token_state(output)
        if state is None or state.frozen:
            raise ValueError("ordinary lineage requires active tokens")
        return state

    def _mint(self, transaction: Transaction, parent: Transaction) -> _Operation:
        if transaction.inputs[0].vout != 0 or len(transaction.outputs) < 3:
            raise ValueError("not a recognized mint transition")
        preceding = [transaction]
        visited = {transaction.txid_wire()}
        state = parent
        while True:
            if (state.txid_wire() in visited or not state.inputs or not state.outputs
                    or not state.outputs[0].script.startswith(self.mint_policy.state_marker)):
                raise ValueError("mint lineage does not reach the issuance anchor")
            visited.add(state.txid_wire())
            previous = state.inputs[0]
            if previous.outpoint() == self.mint_policy.asset.issuance_outpoint:
                self.prevout(previous)
                break
            if previous.vout != 0:
                raise ValueError("mint state did not consume vout zero")
            preceding.append(state)
            state, _ = self.prevout(previous)
        recover_mint_state(self.mint_policy, state, tuple(reversed(preceding)))
        return _Operation({1: self.active_state(transaction.outputs[1])}, ())

    def _regular(self, tx: Transaction, parent: Transaction, profile: MimoProfile) -> _Operation:
        self.token_policy.selected_verifier(tx, parent.serialize())
        if len(tx.inputs) != profile.incoming + 1 or len(tx.outputs) != profile.flow_outputs:
            raise ValueError("transaction does not match its exact verifier profile")
        inputs, quantity = [], 0
        for spend in tx.inputs[1:]:
            _, output = self.prevout(spend)
            quantity += self.active_state(output).quantity
            inputs.append((spend.txid, spend.vout))
        tokens = {i: self.active_state(tx.outputs[i]) for i in range(profile.outgoing)}
        outgoing = sum(token.quantity for token in tokens.values())
        burn_vout = None
        if profile.burn:
            burn_vout = profile.outgoing
            outgoing += read_burn(tx, burn_vout, self.mint_policy.asset).quantity
        if not 0 < quantity < 2**64 or quantity != outgoing:
            raise ValueError("token lineage does not conserve quantity")
        return _Operation(tokens, tuple(inputs), burn_vout)

    def _admin(self, tx: Transaction) -> _Operation:
        inputs, tokens = [], {}
        for vin, spend in enumerate(tx.inputs):
            _, previous = self.prevout(spend)
            before = self.token_state(previous)
            if before is None:
                continue
            if vin >= len(tx.outputs):
                raise ValueError("administrative transition omits its successor")
            after = self.token_state(tx.outputs[vin])
            if (after is None or after.frozen == before.frozen or after.owner != before.owner
                    or after.quantity != before.quantity or previous.value != tx.outputs[vin].value):
                raise ValueError("administrative transition changed the token identity or quantity")
            preimage = preimage_forkid(tx, vin, previous.value, previous.script, FORKID_SINGLE)
            suffix = push(preimage) + asm("OP_1")
            if not spend.script.endswith(suffix):
                raise ValueError("input did not use the canonical administrative witness")
            signature = spend.script[:-len(suffix)]
            if not (10 <= len(signature) <= 74 and signature == push(signature[1:])
                    and signature[-1] == FORKID_ALL):
                raise ValueError("invalid administrative authorization encoding")
            inputs.append((spend.txid, spend.vout))
            tokens[vin] = after
        for index, output in enumerate(tx.outputs):
            if index not in tokens and self.token_state(output) is not None:
                raise ValueError("token output is not linked to an authorized administrative input")
        if not tokens:
            raise ValueError("no recognized asset transition")
        return _Operation(tokens, tuple(inputs))

    def classify(self, txid: bytes) -> _Operation:
        if txid not in self.operations:
            tx = self.load(txid)
            if not tx.inputs or len({item.outpoint() for item in tx.inputs}) != len(tx.inputs):
                raise ValueError("invalid or repeated lineage input")
            parent, first = self.prevout(tx.inputs[0])
            if first.script.startswith(self.mint_policy.state_marker):
                op = self._mint(tx, parent)
            elif first.script in self.lineage._profile_locks:
                op = self._regular(tx, parent, self.lineage._profile_locks[first.script])
            else:
                op = self._admin(tx)
            self.operations[txid] = op
        return self.operations[txid]

    def verify(self, requested: bytes) -> _Operation:
        # Validate each distinct transaction once without depending on Python's
        # recursion limit. Every spent token vout must itself be an approved
        # output of the actual parent transaction.
        todo = [(requested, False)]
        pending: set[bytes] = set()
        while todo:
            txid, expanded = todo.pop()
            if txid in self.verified:
                continue
            operation = self.classify(txid)
            if expanded:
                if any(vout not in self.operations[parent].tokens for parent, vout in operation.parents):
                    raise ValueError("input refers to an unauthenticated token vout")
                pending.remove(txid)
                self.verified.add(txid)
                continue
            if txid in pending:
                raise ValueError("cyclic token provenance")
            pending.add(txid)
            todo.append((txid, True))
            todo.extend((parent, False) for parent, _ in operation.parents if parent not in self.verified)
        return self.operations[requested]

    def verify_token(self, txid: bytes, vout: int) -> TokenState:
        token = self.verify(txid).tokens.get(vout)
        if token is None:
            raise ValueError("vout is not an authenticated token output")
        return token

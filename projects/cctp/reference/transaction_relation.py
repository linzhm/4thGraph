"""Canonical transaction relation for CCTP development.

This is a host reference, not a recursive proof or a consensus validator.
Parent bytes authenticate content by txid; they do not establish issuance,
confirmation, unspent status, or owner authorization.
"""
from dataclasses import dataclass

from shared.script import asm, push
from shared.transaction import Transaction, hash256, preimage_all
from statement import AssetDescriptor, Slot, fixed, transfer_bytes, uint
from transfer import COMPACT_SCRIPTCODE, verifier_input_guard

TOKEN_DOMAIN = b"BSV/CCTP/token/v1\x00"
MARKER = push(TOKEN_DOMAIN)


@dataclass(frozen=True)
class TokenState:
    asset_id: bytes
    quantity: int
    owner: bytes
    frozen: bool = False

    def encode(self):
        fixed(self.asset_id, 32)
        uint(self.quantity, 8)
        if self.quantity == 0:
            raise ValueError("empty token quantity")
        if len(fixed(self.owner, 33)) != 33 or self.owner[0] not in (2, 3):
            raise ValueError("expected compressed owner key")
        if type(self.frozen) is not bool:
            raise ValueError("expected boolean frozen state")
        return self.asset_id + uint(self.quantity, 8) + self.owner + bytes([self.frozen])


def token_lock(state: TokenState, verifier_lock: bytes) -> bytes:
    """Versioned metadata plus exact verifier guard and holder authorization.

    Frozen outputs fail closed until an administrative branch is implemented.
    Production signing remains the responsibility of an external signer.
    """
    if not verifier_lock:
        raise ValueError("missing verifier lock")
    return (
        MARKER + push(state.encode()) + asm("OP_2DROP")
        + (asm("OP_0 OP_VERIFY") if state.frozen else b"")
        + verifier_input_guard(verifier_lock)
        + asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
        + push(b"\x41") + asm("OP_EQUALVERIFY")
        + push(state.owner) + asm("OP_CHECKSIG")
    )


def read_token(script: bytes, verifier_lock: bytes) -> TokenState | None:
    if not script.startswith(MARKER):
        return None
    # Exactly 74 metadata bytes, using the canonical direct push.
    offset = len(MARKER)
    raw = script[offset + 1:offset + 75]
    if len(raw) != 74 or raw[73] not in (0, 1):
        raise ValueError("invalid token metadata")
    state = TokenState(raw[:32], int.from_bytes(raw[32:40], "little"), raw[40:73], bool(raw[73]))
    if token_lock(state, verifier_lock) != script:
        raise ValueError("noncanonical or incorrect token lock")
    return state


@dataclass(frozen=True)
class BoundTransfer:
    statement: bytes
    preimage: bytes
    prevouts: bytes
    outputs: bytes
    input_states: tuple[TokenState, ...]
    output_states: tuple[TokenState, ...]


def bind_transfer(
    asset: AssetDescriptor, verifier_key_id: bytes, tx: Transaction,
    parent_bytes: tuple[bytes, ...], verifier_lock: bytes,
    inputs: tuple[Slot, ...], outputs: tuple[Slot, ...],
    *, authenticated_preimage: bytes,
) -> BoundTransfer:
    """Match every declared slot to actual parents and successor locks.

    Require one canonical raw parent per actual input, including funding inputs.
    The caller must authenticate the supplied preimage using input zero's
    CHECKSIG. No provenance claim is made by this function.
    """
    if len(parent_bytes) != len(tx.inputs) or not tx.inputs:
        raise ValueError("missing input parent")
    parents = tuple(Transaction.parse(raw) for raw in parent_bytes)
    for txin, parent in zip(tx.inputs, parents, strict=True):
        if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
            raise ValueError("incorrect input parent or vout")
    # The reusable guard enforces vout zero and a one-input/one-output parent.
    verifier_parent = parents[0]
    if (tx.inputs[0].vout != 0 or len(verifier_parent.inputs) != 1
            or len(verifier_parent.outputs) != 1 or len(verifier_parent.inputs[0].script) >= 253):
        raise ValueError("unsupported verifier parent shape")
    statement = transfer_bytes(asset, verifier_key_id, tx, verifier_parent, verifier_lock,
                               inputs, outputs, script_code=COMPACT_SCRIPTCODE)
    expected = preimage_all(tx, 0, verifier_parent.outputs[0].value, COMPACT_SCRIPTCODE)
    if authenticated_preimage != expected:
        raise ValueError("preimage does not authenticate this transaction")
    prevouts = b"".join(item.outpoint() for item in tx.inputs)
    serialized_outputs = b"".join(item.serialize() for item in tx.outputs)
    if (expected[4:36] != hash256(prevouts)
            or expected[-40:-8] != hash256(serialized_outputs)):
        raise ValueError("transaction serialization mismatch")

    def collect(indexed_scripts):
        slots, states = [], []
        for index, script in indexed_scripts:
            state = read_token(script, verifier_lock)
            if state is None:
                continue
            if state.asset_id != asset.asset_id():
                raise ValueError("wrong token asset")
            if state.frozen:
                raise ValueError("frozen token in ordinary transfer")
            slots.append(Slot(index, state.quantity))
            states.append(state)
        return tuple(slots), tuple(states)

    actual_inputs, incoming = collect(
        (i, parents[i].outputs[tx.inputs[i].vout].script) for i in range(1, len(tx.inputs)))
    actual_outputs, outgoing = collect((i, output.script) for i, output in enumerate(tx.outputs))
    if inputs != actual_inputs or outputs != actual_outputs:
        raise ValueError("declared slots do not match all actual token outputs")
    return BoundTransfer(statement, expected, prevouts, serialized_outputs, incoming, outgoing)

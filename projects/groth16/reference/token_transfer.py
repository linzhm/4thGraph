"""Experimental owned token output and reference transfer relation."""

from dataclasses import dataclass

from shared.script import asm, push
from shared.transaction import Transaction
from transfer import shared_guard_lock, verifier_input_guard

TAG = b"BSV/Groth16/token/v1\x00"
MARKER = push(TAG)


@dataclass(frozen=True)
class TokenState:
    issuance: bytes
    quantity: int
    owner: bytes


def owned_token_lock(state: TokenState, verifier_lock: bytes, *, shared_guard=False) -> bytes:
    if len(state.issuance) != 36 or not 0 < state.quantity < 2**64:
        raise ValueError("invalid issuance outpoint or token quantity")
    if len(state.owner) != 33 or state.owner[0] not in (2, 3):
        raise ValueError("expected a compressed secp256k1 owner key")
    checked_lock = shared_guard_lock(verifier_lock) if shared_guard else verifier_lock
    return (
        MARKER + push(state.issuance + state.quantity.to_bytes(8, "little") + state.owner)
        + asm("OP_2DROP") + verifier_input_guard(checked_lock, input_index=int(shared_guard))
        + asm("OP_DEPTH OP_1 OP_NUMEQUALVERIFY OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP")
        + push(b"\x41") + asm("OP_EQUALVERIFY")
        + push(state.owner) + asm("OP_CHECKSIG")
    )


def read_token_state(script: bytes, verifier_lock: bytes, *, shared_guard=False) -> TokenState | None:
    if not script.startswith(MARKER):
        return None
    # 77-byte metadata push uses PUSHDATA1, then the exact covenant follows.
    metadata = script[len(MARKER) + 2:len(MARKER) + 79]
    if len(metadata) != 77:
        raise ValueError("truncated token state")
    state = TokenState(metadata[:36], int.from_bytes(metadata[36:44], "little"), metadata[44:])
    if owned_token_lock(state, verifier_lock, shared_guard=shared_guard) != script:
        raise ValueError("unexpected token covenant")
    return state


def check_transfer_relation(
    transaction: Transaction, parents: tuple[Transaction, ...],
    issuance: bytes, verifier_lock: bytes, authenticated_tokens: set[bytes], *, shared_guard=False,
) -> None:
    """Reference relation. Provenance must authenticate the supplied set of outpoints."""
    if len(transaction.inputs) != len(parents):
        raise ValueError("missing input parent")
    if shared_guard and len(parents) < 2:
        raise ValueError("missing shared guard input")
    input_sum = output_sum = 0
    seen = set()
    for index, (txin, parent) in enumerate(zip(transaction.inputs, parents, strict=True)):
        outpoint = txin.outpoint()
        if outpoint in seen:
            raise ValueError("duplicate input")
        seen.add(outpoint)
        if txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
            raise ValueError("input parent mismatch")
        script = parent.outputs[txin.vout].script
        if index == 0:
            if txin.vout != 0 or script != verifier_lock:
                raise ValueError("expected verifier at input zero")
            continue
        if shared_guard and index == 1:
            if txin.vout != 0 or script != shared_guard_lock(verifier_lock):
                raise ValueError("expected shared guard at input one")
            continue
        state = read_token_state(script, verifier_lock, shared_guard=shared_guard)
        if state is not None:
            if state.issuance != issuance or outpoint not in authenticated_tokens:
                raise ValueError("unauthenticated token input")
            input_sum += state.quantity
    for output in transaction.outputs:
        state = read_token_state(output.script, verifier_lock, shared_guard=shared_guard)
        if state is not None:
            if state.issuance != issuance:
                raise ValueError("wrong output issuance")
            output_sum += state.quantity
    if input_sum == 0 or input_sum != output_sum:
        raise ValueError("token quantities do not conserve")

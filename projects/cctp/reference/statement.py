"""Canonical v1 host encoding for the experimental BSV bridge transfer."""

from dataclasses import dataclass

from shared.script import asm
from shared.transaction import Transaction, hash256, preimage_all

ASSET_DOMAIN = b"BSV/CCTP/asset/v1\x00"
TRANSFER_DOMAIN = b"BSV/CCTP/transfer/v1\x00"


def uint(value: int, size: int) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << (8 * size):
        raise ValueError(f"expected uint{size * 8}")
    return value.to_bytes(size, "little")


def fixed(value: bytes, size: int) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f"expected {size} bytes")
    return value


@dataclass(frozen=True)
class AssetDescriptor:
    network: int
    issuance_outpoint: bytes
    decimals: int
    reserve_domain: int
    reserve_asset: bytes
    policy_id: bytes

    def encode(self) -> bytes:
        return (
            ASSET_DOMAIN
            + uint(self.network, 4)
            + fixed(self.issuance_outpoint, 36)
            + uint(self.decimals, 1)
            + uint(self.reserve_domain, 4)
            + fixed(self.reserve_asset, 32)
            + fixed(self.policy_id, 32)
        )

    def asset_id(self) -> bytes:
        return hash256(self.encode())


@dataclass(frozen=True)
class Slot:
    index: int
    quantity: int


def encode_slots(slots: tuple[Slot, ...], limit: int, first: int) -> bytes:
    if not slots or len(slots) > 256:
        raise ValueError("expected 1 to 256 token slots")
    encoded = bytearray(uint(len(slots), 2))
    for slot in slots:
        if type(slot.index) is not int or not first <= slot.index < limit:
            raise ValueError("token slot out of order or out of bounds")
        if slot.quantity == 0:
            raise ValueError("empty token slot")
        encoded += uint(slot.index, 4) + uint(slot.quantity, 8)
        first = slot.index + 1
    return bytes(encoded)


def transfer_bytes(
    asset: AssetDescriptor,
    verifier_key_id: bytes,
    tx: Transaction,
    verifier_parent: Transaction,
    verifier_lock: bytes,
    inputs: tuple[Slot, ...],
    outputs: tuple[Slot, ...],
    *,
    script_code: bytes | None = None,
) -> bytes:
    """Build the reference statement with the shared verifier at input zero."""
    if not tx.inputs or len({item.outpoint() for item in tx.inputs}) != len(tx.inputs):
        raise ValueError("missing or duplicate input")
    verifier = tx.inputs[0]
    if verifier.txid != verifier_parent.txid_wire() or not 0 <= verifier.vout < len(verifier_parent.outputs):
        raise ValueError("incorrect verifier parent")
    previous_output = verifier_parent.outputs[verifier.vout]
    if not verifier_lock or previous_output.script != verifier_lock:
        raise ValueError("incorrect verifier lock")
    input_slots = encode_slots(inputs, len(tx.inputs), 1)
    output_slots = encode_slots(outputs, len(tx.outputs), 0)
    input_total = sum(item.quantity for item in inputs)
    uint(input_total, 8)
    if input_total != sum(item.quantity for item in outputs):
        raise ValueError("quantity is not conserved")
    if script_code is None:
        script_code = verifier_lock
    elif not script_code or not verifier_lock.endswith(asm("OP_CODESEPARATOR") + script_code):
        raise ValueError("incorrect compact verifier suffix")
    preimage = preimage_all(tx, 0, previous_output.value, script_code)
    return (
        TRANSFER_DOMAIN
        + asset.asset_id()
        + fixed(verifier_key_id, 32)
        + hash256(preimage)
        + input_slots
        + output_slots
    )


def public_inputs(statement: bytes) -> tuple[int, int]:
    digest = hash256(statement)
    return int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")

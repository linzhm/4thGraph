"""Build deterministic freeze/unfreeze vectors using the existing Script control."""

from dataclasses import replace
from hashlib import sha256
import json

from operational_token import FLAG_OFFSET, FORKID_SINGLE, TokenPolicy, freeze_witness
from shared.chain_gang import validate_at_heights
from shared.script import asm
from shared.transaction import Input, Output, Transaction, blob, hash256, preimage_forkid
from statement import AssetDescriptor
from test_operational_token import fixture_signer
from transaction_relation import TokenState


DOMAIN = b"BSV/CCTP/freeze-transition/v1\x00"


def pack_state(output, policy):
    state = policy.parse(output.script)
    normalized = output.script[:FLAG_OFFSET] + b"\x00" + output.script[FLAG_OFFSET + 1:]
    return output.value.to_bytes(8, "little") + state.encode() + sha256(blob(normalized)).digest()


def coin(label, output):
    return Transaction((Input(hash256(label), 0),), (output,))


def control(label, parent, fee, policy, signer, freeze):
    prior = parent.outputs[0]
    state = policy.parse(prior.script)
    successor = Output(prior.value, policy.lock(replace(state, frozen=freeze)))
    tx = Transaction((Input(parent.txid_wire(), 0, sequence=456), Input(fee.txid_wire(), 0)),
                     (successor,), version=2, locktime=123)
    signed = tx.with_script(0, freeze_witness(tx, 0, parent, policy, signer))
    validate_at_heights(signed, (parent, fee), spend_height=200, activation_height=2, utxo_heights=(3, 3))
    context = hash256(preimage_forkid(signed, 0, prior.value, prior.script, FORKID_SINGLE))
    encoded = (DOMAIN + signed.inputs[0].outpoint() + bytes(4) + context
               + pack_state(prior, policy) + pack_state(successor, policy))
    return signed, {"case": label, "statement": encoded.hex(), "digest": hash256(encoded).hex()}


def main():
    # Public, deterministic signing keys are restricted to the offline fixture.
    holder, _ = fixture_signer(11)
    authority, signer = fixture_signer(12)
    policy = TokenPolicy((asm("OP_1"),), authority)
    anchor = Input(hash256(b"CCTP freeze circuit isolated offline fixture"), 0)
    asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)
    state = TokenState(asset.asset_id(), 640, holder)
    parent = Transaction((anchor,), (Output(1500, policy.lock(state)),))
    fees = tuple(coin(label, Output(3000, asm("OP_1"))) for label in (b"fixture fee A", b"fixture fee B"))
    frozen, freeze = control("freeze", parent, fees[0], policy, signer, True)
    _, unfreeze = control("unfreeze", frozen, fees[1], policy, signer, False)
    print(json.dumps([freeze, unfreeze], indent=2))


if __name__ == "__main__":
    main()

"""Issuer-only token shell for the isolated freeze proof at verifier vin 1."""

from dataclasses import replace
from hashlib import sha256

from freeze_probe import ALL, DOMAIN, METADATA_PREFIX, METADATA_SIZE, SINGLE, _state_script, paired_successor
from freeze_probe import statement as paired_statement
from mimo_verifier import _match_prefix, _split
from shared.script import asm, push
from shared.transaction import blob, hash256, preimage_forkid
from statement import fixed
from statement_receipt import RECEIPT_PREFIX, receipt_output as statement_receipt
from transfer import verifier_input_script_hash


def statement(tx, previous):
    """Return the common freeze statement for paired vout 0 before or after adding its receipt."""
    if len(tx.outputs) == 2:
        # ForkID SINGLE at index zero commits only the serialized paired output.
        tx = replace(tx, outputs=tx.outputs[:1])
    return paired_statement(tx, previous)


def receipt_output(tx, previous):
    return statement_receipt(hash256(statement(tx, previous)))


def transaction_witness(tx, previous, verifier_funding, signer):
    """Request the separate issuer ALL signature over the exact two-output transaction."""
    receipt = receipt_output(tx, previous)
    if len(tx.outputs) != 2 or tx.outputs[1] != receipt:
        raise ValueError("expected exact statement receipt at vout 1")
    if (tx.inputs[1].txid != verifier_funding.txid_wire() or tx.inputs[1].vout != 0
            or len(verifier_funding.inputs) != 1 or len(verifier_funding.inputs[0].script) >= 253
            or len(verifier_funding.outputs) != 1):
        raise ValueError("expected real one-input one-output verifier funding at vin 1, vout 0")
    full = preimage_forkid(tx, 0, previous.value, previous.script, ALL)
    return b"".join(map(push, (
        signer(hash256(full)) + bytes([ALL]), verifier_funding.serialize(),
        b"".join(item.outpoint() for item in tx.inputs), tx.outputs[0].serialize(), receipt.serialize(), full,
    )))


def _single_digest():
    """From [paired TxOut, ALL preimage], retain both and append the reconstructed SINGLE digest."""
    return (
        # Retain version and hashPrevouts, replacing the next 32 bytes (hashSequence).
        asm("OP_DUP 36 OP_SPLIT 32 OP_SPLIT OP_NIP OP_SWAP") + push(bytes(32)) + asm("OP_CAT OP_SWAP")
        # Keep the same outpoint, script field, amount and sequence. Replace hashOutputs.
        + asm("OP_SIZE 40 OP_SUB OP_SPLIT 32 OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_DROP"
              " OP_4 OP_PICK OP_HASH256 OP_SWAP")
        + push(SINGLE.to_bytes(4, "little")) + asm("OP_CAT OP_CAT OP_CAT OP_CAT OP_HASH256")
    )


def token_statement_script(freeze_key, verifier_script_field_hash):
    """Bind the actual token spend, issuer, verifier funding and canonical statement receipt."""
    return (
        # Witness [issuer DER+41, funding raw, prevouts, paired TxOut, receipt TxOut, ALL preimage].
        asm("OP_DEPTH OP_6 OP_NUMEQUALVERIFY OP_3 OP_PICK OP_SIZE 72 OP_NUMEQUALVERIFY 36 OP_SPLIT OP_DROP")
        + asm("OP_OVER 68 OP_SPLIT OP_NIP 36 OP_SPLIT OP_DROP OP_EQUALVERIFY")
        # Reuse the native 0x41 PUSHTX check while authenticating the actual vin 1 funding lock.
        + asm("OP_4 OP_ROLL OP_4 OP_ROLL OP_2 OP_PICK") + verifier_input_script_hash(input_index=1)
        + push(fixed(verifier_script_field_hash, 32)) + asm("OP_EQUALVERIFY")
        # [issuer signature, paired TxOut, receipt TxOut, ALL preimage]. Only these two outputs are allowed.
        + asm("OP_DUP OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP"
              " OP_3 OP_PICK OP_3 OP_PICK OP_CAT OP_HASH256 OP_EQUALVERIFY")
        + asm("OP_3 OP_ROLL OP_DUP OP_SIZE OP_1SUB OP_SPLIT OP_NIP") + push(bytes([ALL]))
        + asm("OP_EQUALVERIFY") + push(fixed(freeze_key, 33)) + asm("OP_CHECKSIGVERIFY")
        + asm("OP_SWAP") + _match_prefix(RECEIPT_PREFIX)
        + asm("OP_SIZE 32 OP_NUMEQUALVERIFY OP_TOALTSTACK")
        # Ordered statement prefix: true vin 0 outpoint, paired index 0 and exact SINGLE digest.
        + _single_digest() + asm("OP_TOALTSTACK OP_DUP 68 OP_SPLIT OP_NIP 36 OP_SPLIT OP_DROP")
        + push(bytes(4)) + asm("OP_CAT OP_FROMALTSTACK OP_CAT OP_TOALTSTACK")
        # Produce state records from the actual input and paired vout 0, then compare the receipt digest.
        + _split(104) + asm("OP_NIP OP_SIZE 52 OP_SUB OP_SPLIT OP_8 OP_SPLIT OP_DROP OP_SWAP")
        + _state_script() + asm("OP_SWAP OP_8 OP_SPLIT") + _state_script()
        + asm("OP_CAT OP_FROMALTSTACK OP_SWAP OP_CAT") + push(DOMAIN)
        + asm("OP_SWAP OP_CAT OP_HASH256 OP_FROMALTSTACK OP_EQUAL")
    )


def lock(state, freeze_key, verifier_lock):
    """Build an isolated token lock with an exact approved independent Groth16 lock."""
    if type(verifier_lock) is not bytes or not verifier_lock:
        raise ValueError("expected the full verifier locking script")
    return (
        METADATA_PREFIX + fixed(state.encode(), METADATA_SIZE) + asm("OP_2DROP")
        + token_statement_script(freeze_key, sha256(blob(verifier_lock)).digest())
    )

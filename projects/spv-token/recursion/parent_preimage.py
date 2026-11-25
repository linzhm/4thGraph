"""Reconstruct a predecessor's compact SIGHASH_ALL preimage from raw bytes."""

from hashlib import sha256

from shared.script import asm, push
from shared.transaction import blob
from statement import TRANSFER_DOMAIN, fixed
from transfer import COMPACT_SCRIPTCODE


def _compact_size():
    """Split one canonical CompactSize up to uint32, leaving payload and length."""
    unsigned = push(b"\x00") + asm("OP_CAT OP_BIN2NUM")
    return (
        asm("OP_1 OP_SPLIT OP_SWAP") + unsigned + asm("OP_DUP 253 OP_LESSTHAN OP_NOTIF")
        + asm("OP_DUP 253 OP_NUMEQUAL OP_IF OP_DROP OP_2 OP_SPLIT OP_SWAP") + unsigned
        + asm("OP_DUP 252 OP_GREATERTHAN OP_VERIFY OP_ELSE")
        + asm("254 OP_NUMEQUALVERIFY OP_4 OP_SPLIT OP_SWAP") + unsigned
        + asm("OP_DUP 65535 OP_GREATERTHAN OP_VERIFY OP_ENDIF OP_ENDIF")
    )


def _count(count):
    return asm("OP_1 OP_SPLIT OP_SWAP") + push(bytes([count])) + asm("OP_EQUALVERIFY")


def _read_input():
    return asm("36 OP_SPLIT") + _compact_size() + asm("OP_SPLIT OP_NIP OP_4 OP_SPLIT")


def _skip_output():
    return asm("8 OP_SPLIT OP_NIP") + _compact_size() + asm("OP_SPLIT OP_NIP")


def predecessor_preimage(verifier_script_hash):
    """Convert [authenticated predecessor raw, verifier funding raw] to [preimage].

    The predecessor profile has two inputs (verifier at input zero) and two
    outputs. Verifier funding has one input and one output. The caller binds
    the predecessor raw to the child's actual input txid and vout and supplies
    the trusted leaf verifier script-field SHA256. This fragment authenticates
    the verifier funding txid, validates its lock, and interprets its amount.
    """
    fixed(verifier_script_hash, 32)
    return (
        # Read the outpoints and sequences, skipping both unlocking scripts.
        asm("OP_SWAP OP_4 OP_SPLIT OP_SWAP OP_TOALTSTACK") + _count(2)
        + _read_input() + _read_input() + _count(2)
        # Validate two serialized outputs, then hash the same raw bytes.
        + asm("OP_SIZE OP_4 OP_SUB OP_SPLIT OP_OVER") + _skip_output() * 2
        + asm("OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP OP_SWAP OP_HASH256 OP_SWAP"
              " OP_TOALTSTACK OP_TOALTSTACK")
        # Stack [funding, verifier outpoint, seq0, token outpoint, seq1].
        + asm("OP_2 OP_PICK OP_OVER OP_CAT OP_HASH256 OP_TOALTSTACK"
              " OP_3 OP_PICK OP_2 OP_PICK OP_CAT OP_HASH256 OP_TOALTSTACK OP_2DROP"
              " OP_TOALTSTACK OP_DUP OP_TOALTSTACK 32 OP_SPLIT")
        + push(bytes(4)) + asm("OP_EQUALVERIFY OP_OVER OP_HASH256 OP_EQUALVERIFY OP_4 OP_SPLIT OP_NIP")
        # Read the spend value from txid-authenticated funding vout zero.
        + _count(1) + _read_input() + asm("OP_ROT OP_DROP OP_SWAP OP_DROP") + _count(1)
        + asm("8 OP_SPLIT OP_SIZE OP_4 OP_SUB OP_SPLIT OP_DROP OP_SHA256")
        + push(verifier_script_hash) + asm("OP_EQUALVERIFY OP_FROMALTSTACK")
        # Outpoint, scriptCode, sats, sequence; then hashes, locktime and type.
        + push(blob(COMPACT_SCRIPTCODE)) + asm("OP_CAT OP_SWAP OP_CAT OP_FROMALTSTACK OP_CAT"
                                              " OP_FROMALTSTACK OP_FROMALTSTACK OP_CAT OP_SWAP OP_CAT"
                                              " OP_FROMALTSTACK OP_CAT OP_FROMALTSTACK OP_CAT"
                                              " OP_FROMALTSTACK OP_SWAP OP_CAT")
        + push(b"\x41\x00\x00\x00") + asm("OP_CAT")
    )


def verifier_funding_script_hash(lock):
    return sha256(blob(lock)).digest()


def predecessor_statement_digest(asset_id, leaf_key_id, verifier_script_hash):
    """Consume [encoded slots, authenticated parent raw, funding raw].

    The leaf verifier's relation must check the supplied slots against the
    authenticated parent preimage. Its digest is used by the recursive proof.
    """
    identity = TRANSFER_DOMAIN + fixed(asset_id, 32) + fixed(leaf_key_id, 32)
    return (predecessor_preimage(verifier_script_hash) + asm("OP_HASH256") + push(identity)
            + asm("OP_SWAP OP_CAT OP_SWAP OP_CAT OP_HASH256"))

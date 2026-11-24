"""Host reference for the transaction statement of a per-transfer verifier."""

from dataclasses import dataclass
from hashlib import sha256

from shared.pushtx import PUBLIC, binding_der
from shared.script import asm, number, push
from shared.transaction import FORKID, SIGHASH_ALL, Transaction, blob, hash256, preimage_forkid

DOMAIN = b"BSV/Groth16/transfer/v1\x00"
COMPACT_DOMAIN = b"BSV/Groth16/transfer/v2\x00"
COMPACT_SCRIPTCODE = push(PUBLIC) + asm("OP_CHECKSIG")
COMPACT_SUFFIX = asm("OP_CODESEPARATOR") + COMPACT_SCRIPTCODE


@dataclass(frozen=True)
class TransferStatement:
    issuance_outpoint: bytes
    authorized_lock: bytes
    compact_preimage: bool = False

    def preimage(self, transaction: Transaction, verifier_index: int, funding: Transaction) -> bytes:
        """Reconstruct the current verifier input's authenticated ForkID preimage."""
        if len(self.issuance_outpoint) != 36:
            raise ValueError("expected a 36-byte issuance outpoint")
        if not 0 <= verifier_index < len(transaction.inputs):
            raise ValueError("missing verifier input")
        prevout = transaction.inputs[verifier_index]
        if prevout.txid != funding.txid_wire() or not 0 <= prevout.vout < len(funding.outputs):
            raise ValueError("funding transaction does not match the verifier outpoint")
        spent = funding.outputs[prevout.vout]
        if spent.script != self.authorized_lock:
            raise ValueError("unexpected verifier lock")
        if len({txin.outpoint() for txin in transaction.inputs}) != len(transaction.inputs):
            raise ValueError("duplicate input")
        script_code = spent.script
        if self.compact_preimage:
            if not script_code.endswith(COMPACT_SUFFIX):
                raise ValueError("missing compact verifier suffix")
            script_code = COMPACT_SCRIPTCODE
        return preimage_forkid(
            transaction, verifier_index, spent.value, script_code, FORKID | SIGHASH_ALL,
        )

    def public_inputs(
        self, transaction: Transaction, verifier_index: int, funding: Transaction,
    ) -> tuple[int, int]:
        """Derive ordered public scalars from the actual verifier input and transaction."""
        preimage = self.preimage(transaction, verifier_index, funding)
        domain = COMPACT_DOMAIN if self.compact_preimage else DOMAIN
        digest = hash256(domain + self.issuance_outpoint + hash256(preimage))
        return int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")


def _forkid_all_digest() -> bytes:
    return (
        asm("OP_DUP OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP")
        + push(b"\x41\x00\x00\x00") + asm("OP_EQUALVERIFY OP_HASH256")
    )


def _bind_digest_signature() -> bytes:
    return binding_der() + push(b"\x41") + asm("OP_CAT")


def _authenticate_forkid_all() -> bytes:
    return (
        _forkid_all_digest() + asm("OP_DUP") + _bind_digest_signature()
        + push(PUBLIC) + asm("OP_CHECKSIGVERIFY")
    )


def compact_verifier_binding() -> bytes:
    """Enforce both the preceding verifier and deferred current-input check."""
    return asm("OP_VERIFY OP_FROMALTSTACK") + _bind_digest_signature() + COMPACT_SUFFIX


def digest_limbs_script() -> bytes:
    """Consume a 32-byte digest and leave two unsigned 128-bit scalars."""
    reverse16 = asm("OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK") * 15 + asm("OP_FROMALTSTACK OP_CAT") * 15
    unsigned_limb = reverse16 + push(b"\x00") + asm("OP_CAT OP_BIN2NUM")
    return asm("16 OP_SPLIT OP_SWAP") + unsigned_limb + asm("OP_SWAP") + unsigned_limb


def compact_preimage_digest_script() -> bytes:
    """Hash a compact ForkID ALL preimage and save a copy for CHECKSIG."""
    return (
        asm("OP_SIZE") + number(157 + len(COMPACT_SCRIPTCODE)) + asm("OP_NUMEQUALVERIFY")
        + _forkid_all_digest() + asm("OP_DUP OP_TOALTSTACK")
    )


def statement_script(issuance_outpoint: bytes, *, compact_preimage=False) -> bytes:
    """Leave both public scalars. Compact mode saves the digest for the final CHECKSIG."""
    if len(issuance_outpoint) != 36:
        raise ValueError("expected a 36-byte issuance outpoint")
    if compact_preimage:
        prefix = compact_preimage_digest_script()
        domain = COMPACT_DOMAIN
    else:
        prefix = _authenticate_forkid_all()
        domain = DOMAIN
    return (
        prefix + push(domain + issuance_outpoint)
        + asm("OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script()
    )


def verifier_input_guard(verifier_lock: bytes, *, input_index: int = 0) -> bytes:
    """Consume verifier parent bytes, serialized prevouts and a ForkID ALL preimage.

    The selected output is vout zero and its parent has one input with a one-byte
    script length and one output. The guard commits to the full serialized
    script field with SHA-256. This fragment leaves the owner's checks to
    the enclosing token covenant.
    """
    if type(input_index) is not int or not 0 <= input_index <= 1:
        raise ValueError("expected verifier at input zero or shared guard at input one")
    skip = number(input_index * 36) + asm("OP_SPLIT OP_NIP") if input_index else b""
    return (
        asm("OP_DUP OP_TOALTSTACK") + _authenticate_forkid_all()
        + asm("OP_DROP OP_FROMALTSTACK OP_4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP "
              "OP_OVER OP_HASH256 OP_EQUALVERIFY")
        + skip + asm("36 OP_SPLIT OP_DROP OP_OVER OP_HASH256")
        + push(bytes(4)) + asm("OP_CAT OP_EQUALVERIFY "
                              "41 OP_SPLIT OP_SWAP OP_4 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_DROP")
        + push(b"\x01") + asm("OP_EQUALVERIFY "
                              "OP_1 OP_SPLIT OP_SWAP")
        + push(b"\x00") + asm("OP_CAT OP_BIN2NUM OP_DUP 0 253 OP_WITHIN OP_VERIFY "
                              "OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_NIP "
                              "OP_1 OP_SPLIT OP_SWAP")
        + push(b"\x01") + asm("OP_EQUALVERIFY 8 OP_SPLIT OP_NIP "
                              "OP_SIZE OP_4 OP_SUB OP_SPLIT OP_DROP")
        + asm("OP_SHA256") + push(sha256(blob(verifier_lock)).digest()) + asm("OP_EQUALVERIFY")
    )



def shared_guard_lock(verifier_lock: bytes) -> bytes:
    """A compact vin[1] lock that enforces the full verifier at vin[0]."""
    return asm("OP_DEPTH OP_3 OP_NUMEQUALVERIFY") + verifier_input_guard(verifier_lock) + asm("OP_1")

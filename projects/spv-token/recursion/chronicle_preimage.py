"""Host normalization of the shared verifier's ForkID and Chronicle ALL preimages."""

from dataclasses import dataclass

from shared.transaction import CHRONICLE, FORKID, SIGHASH_ALL, Transaction, hash256, preimage_forkid, preimage_otda

LEGACY_ALL = FORKID | SIGHASH_ALL
CHRONICLE_ALL = CHRONICLE | LEGACY_ALL
VERIFIER_SEQUENCES = {LEGACY_ALL: 0x80000041, CHRONICLE_ALL: 0x80000061}


@dataclass(frozen=True)
class NormalizedAllPreimage:
    sighash_type: int
    version: int
    prevouts: bytes
    hash_sequence: bytes
    current_outpoint: bytes
    current_sequence: int
    previous_amount: int
    outputs: bytes
    locktime: int
    digest: bytes

    @property
    def hash_prevouts(self) -> bytes:
        return hash256(self.prevouts)

    @property
    def hash_outputs(self) -> bytes:
        return hash256(self.outputs)


def normalize_shared_verifier_preimage(
    tx: Transaction, verifier_index: int, verifier_funding: Transaction, authenticated_preimage: bytes,
    *, sighash_type: int, script_code: bytes,
) -> NormalizedAllPreimage:
    """Match the selected ALL preimage and extract the same transaction fields.

    The caller establishes the actual transaction, signature branch and
    node-cleaned scriptCode for its executed CODESEPARATOR. Signature validity
    and Chronicle activation are separate checks. The funded amount comes
    from the actual verifier prevout in either branch.
    """
    if type(sighash_type) is not int or sighash_type not in (LEGACY_ALL, CHRONICLE_ALL):
        raise ValueError("expected the shared verifier's 0x41 or 0x61 ALL signature type")
    if type(verifier_index) is not int or not 0 <= verifier_index < len(tx.inputs):
        raise ValueError("invalid shared verifier input position")
    if type(script_code) is not bytes or type(authenticated_preimage) is not bytes:
        raise ValueError("expected scriptCode and preimage bytes")

    current = tx.inputs[verifier_index]
    if (type(current.vout) is not int or not 0 <= current.vout < len(verifier_funding.outputs)
            or current.txid != verifier_funding.txid_wire()):
        raise ValueError("incorrect actual verifier funding outpoint")
    previous_amount = verifier_funding.outputs[current.vout].value

    if sighash_type == LEGACY_ALL:
        expected = preimage_forkid(tx, verifier_index, previous_amount, script_code, sighash_type)
    else:
        expected = preimage_otda(tx, verifier_index, script_code, sighash_type)
    # Whole-byte matching against the canonical encoding bounds the check by
    # the actual transaction. In OTDA this pins each vin, the selected script
    # field, empty scripts at all other vins, every CompactSize, and EOF.
    if authenticated_preimage != expected:
        raise ValueError("ALL preimage does not match the actual shared verifier input")

    return NormalizedAllPreimage(
        sighash_type=sighash_type,
        version=tx.version,
        prevouts=b"".join(txin.outpoint() for txin in tx.inputs),
        hash_sequence=hash256(b"".join(txin.sequence.to_bytes(4, "little") for txin in tx.inputs)),
        current_outpoint=current.outpoint(),
        current_sequence=current.sequence,
        previous_amount=previous_amount,
        outputs=b"".join(output.serialize() for output in tx.outputs),
        locktime=tx.locktime,
        digest=hash256(authenticated_preimage),
    )


def shared_verifier_sighash(sequence):
    """Recover the ALL branch from its actual disabled-relative-lock sequence."""
    for sighash, bound in VERIFIER_SEQUENCES.items():
        if sequence == bound:
            return sighash
    raise ValueError("incorrect shared verifier ALL signature type sequence")

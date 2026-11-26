"""Prepare the digest and witness for transaction-bound signature templates."""

from dataclasses import dataclass

from fourthgraph.bsv.pushtx import N, R
from fourthgraph.bsv.script import number, push
from fourthgraph.bsv.transaction import (
    CHRONICLE, FORKID, SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_TYPES,
    amount, hash256, preimage_forkid, preimage_otda,
)

DEFAULT_SIGHASH = FORKID | SIGHASH_ALL


@dataclass(frozen=True)
class SpendAuthorization:
    requested_type: int
    preimage: bytes
    companion: bool

    def digest(self):
        return hash256(self.preimage)

    def checked_digest(self):
        digest = self.digest()
        if (int.from_bytes(digest, 'big') + R) % N == 0:
            raise ValueError('degenerate binding digest; rebuild before signing')
        return digest

    def witness(self, signature):
        return push(self.preimage) + push(signature) + number(int(self.companion))


def prepare_authorization(tx, index, previous_amount, sighash, *, ordinary_code, companion_code):
    if type(sighash) is not int or sighash not in SIGHASH_TYPES or not 0 <= index < len(tx.inputs):
        raise ValueError('unsupported sighash or input index')
    amount(previous_amount)
    chronicle = bool(sighash & CHRONICLE)
    companion = chronicle and sighash & 31 == SIGHASH_SINGLE and index >= len(tx.outputs)
    if chronicle and not companion:
        preimage = preimage_otda(tx, index, ordinary_code, sighash)
    else:
        code = companion_code if companion else ordinary_code
        preimage = preimage_forkid(tx, index, previous_amount, code, sighash & ~CHRONICLE)
    return SpendAuthorization(sighash, preimage, companion)

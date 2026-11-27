"""Construct signing messages for the published P2PKH-SM2 payment template."""
from dataclasses import dataclass
from fourthgraph.bsv.transaction import (ANYONECANPAY, CHRONICLE, SIGHASH_SINGLE as SINGLE,
                                SIGHASH_TYPES as SUPPORTED_TYPES, hash256,
                                preimage_forkid, preimage_otda)

ORDINARY_CODE = bytes.fromhex('ac')
COMPANION_CODE = bytes.fromhex('ad68abac')


@dataclass(frozen=True)
class Authorization:
    requested_type: int
    preimage: bytes
    companion: bool

    @property
    def message(self):
        return hash256(self.preimage)


def authorization(tx, index, previous_amount, sighash_type=0x41, *, chronicle_active=True):
    """Generate the message and witness P. Set chronicle_active from the spend context."""
    if type(sighash_type) is not int or sighash_type not in SUPPORTED_TYPES:
        raise ValueError('unsupported sighash type')
    if not 0 <= index < len(tx.inputs):
        raise ValueError('invalid input index')
    if sighash_type & CHRONICLE and not chronicle_active:
        raise ValueError('Chronicle sighash is disabled in this spend context')
    if sighash_type & CHRONICLE:
        if (sighash_type & 0x1f) == SINGLE and index >= len(tx.outputs):
            pre = preimage_forkid(tx, index, previous_amount, COMPANION_CODE, sighash_type ^ CHRONICLE)
            return Authorization(sighash_type, pre, True)
        return Authorization(sighash_type, preimage_otda(tx, index, ORDINARY_CODE, sighash_type), False)
    return Authorization(sighash_type, preimage_forkid(tx, index, previous_amount, ORDINARY_CODE, sighash_type), False)

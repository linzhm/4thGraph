"""Prepare the preimage hash and witness fields for the R1 + PELS reference lock."""

import argparse
from dataclasses import dataclass
from pathlib import Path

from fourthgraph.bsv.script import OPS, push
from fourthgraph.bsv.transaction import Transaction, hash256, preimage_forkid

BIP143_ALL = 0x41
STATE_PREFIX_BYTES = 7


@dataclass(frozen=True)
class PreparedAuthorization:
    digest: bytes
    head: bytes
    tail: bytes

    def unlocking_script(self, public_key, signature):
        """Assemble the supplied X9.63 key and externally produced raw signature."""
        if len(public_key) != 65 or public_key[0] != 4 or len(signature) != 64:
            raise ValueError("expected an uncompressed R1 key and two 32-byte signature scalars")
        return b"".join(map(push, (public_key, signature, self.tail, self.head)))


def prepare_authorization(tx, parent):
    """Prepare a single-input counter spend against its actual previous output.

    The caller approves the transaction and selects a previous output known to
    use this reference lock. The returned digest is the sole signing input.
    """
    if len(tx.inputs) != 1 or not tx.outputs:
        raise ValueError("the reference PELS spend needs one input and an output")
    txin = tx.inputs[0]
    if txin.script or txin.txid != parent.txid_wire() or not 0 <= txin.vout < len(parent.outputs):
        raise ValueError("the unsigned input must select the supplied previous output")
    previous = parent.outputs[txin.vout]
    raw = previous.script
    if len(raw) <= STATE_PREFIX_BYTES or raw[0] != 5 or raw[5] != 0 or raw[6] != OPS["OP_CODESEPARATOR"]:
        raise ValueError("the previous output has the wrong counter state prefix")
    preimage = preimage_forkid(tx, 0, previous.value, raw[STATE_PREFIX_BYTES:], BIP143_ALL)
    # The output hash precedes the four-byte locktime and four-byte sighash.
    return PreparedAuthorization(hash256(preimage), preimage[:-40], preimage[-8:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, required=True, help="hex file containing the previous transaction")
    parser.add_argument("--unsigned", type=Path, required=True, help="hex file containing the unsigned spend")
    args = parser.parse_args()
    try:
        parent = Transaction.parse(bytes.fromhex(args.parent.read_text(encoding="ascii")))
        unsigned = Transaction.parse(bytes.fromhex(args.unsigned.read_text(encoding="ascii")))
        authorization = prepare_authorization(unsigned, parent)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(authorization.digest.hex())


if __name__ == "__main__":
    main()

"""Index-free validation of confirmed payment packets for isolated BSV regtest."""

from dataclasses import dataclass
from time import time

from shared.chain_gang import validate_at_heights
from shared.transaction import Input, Transaction, hash256
from wallet_receipt import BlockInclusion, SpendStatus


# BSV Node v1.2.3 CRegTestParams. Every header uses the genesis difficulty.
REGTEST_GENESIS = bytes.fromhex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")[::-1]
REGTEST_BITS = bytes.fromhex("ffff7f20")
REGTEST_TARGET = 0x7fffff << (8 * (0x20 - 3))


@dataclass(frozen=True)
class RegtestHeaderChain:
    """Verify an offered header chain locally. No network or full-block index."""

    headers: tuple[bytes, ...]

    def __post_init__(self):
        if not isinstance(self.headers, tuple) or not self.headers:
            raise ValueError("expected a nonempty immutable header chain")
        previous = bytes(32)
        times = []
        latest = int(time()) + 2 * 60 * 60
        for height, header in enumerate(self.headers):
            if type(header) is not bytes or len(header) != 80 or header[4:36] != previous:
                raise ValueError("invalid header linkage")
            if header[72:76] != REGTEST_BITS:
                raise ValueError("unexpected regtest difficulty")
            current = hash256(header)
            if int.from_bytes(current, "little") > REGTEST_TARGET:
                raise ValueError("insufficient proof of work")
            if height == 0 and current != REGTEST_GENESIS:
                raise ValueError("unexpected regtest genesis")
            timestamp = int.from_bytes(header[68:72], "little")
            recent = sorted(times[-11:])
            if timestamp > latest or (recent and timestamp <= recent[len(recent) // 2]):
                raise ValueError("invalid header timestamp")
            times.append(timestamp)
            previous = current

    @property
    def chainwork(self):
        return len(self.headers) * ((1 << 256) // (REGTEST_TARGET + 1))

    def adopt(self, candidate):
        """Compare independently validated offers. Keep the adopted chain on ties."""
        if not isinstance(candidate, RegtestHeaderChain):
            raise ValueError("expected a validated regtest chain")
        return candidate if candidate.chainwork > self.chainwork else self

    def confirmations(self, inclusion):
        if (type(inclusion.height) is not int or not 0 <= inclusion.height < len(self.headers)
                or self.headers[inclusion.height] != inclusion.header):
            raise ValueError("block is outside the adopted header chain")
        return len(self.headers) - inclusion.height


@dataclass(frozen=True)
class TxInclusion:
    raw: bytes
    inclusion: BlockInclusion

    def open(self, chain):
        tx = Transaction.parse(self.raw)
        self.inclusion.verify(tx.txid_wire())
        return tx, chain.confirmations(self.inclusion)


@dataclass(frozen=True)
class VerifiedPayment:
    transaction: Transaction
    outpoint: bytes
    confirmations: int
    fee: int
    spend_status: SpendStatus = SpendStatus.UNKNOWN


def verify_receipt(chain, payment, parents, *, txid_wire, vout, expected_output, authenticate,
                   activation_height, minimum_confirmations=1):
    """Authenticate the receipt using only headers and actual direct prevouts.

    The caller's pinned policy must authenticate the creation action and its
    verifier role before Script is replayed. A Merkle inclusion proves no claim
    about subsequent spends of the verified output.
    """
    if type(minimum_confirmations) is not int or minimum_confirmations < 1:
        raise ValueError("minimum confirmations must be positive")
    tx, depth = payment.open(chain)
    if tx.txid_wire() != txid_wire or depth < minimum_confirmations:
        raise ValueError("different payment or insufficient confirmations")
    if type(vout) is not int or not 0 <= vout < len(tx.outputs) or tx.outputs[vout] != expected_output:
        raise ValueError("receipt outpoint, owner, amount or policy mismatch")
    prevouts = tuple(item.outpoint() for item in tx.inputs)
    if not prevouts or len(set(prevouts)) != len(prevouts):
        raise ValueError("empty or duplicate actual prevout")
    if len(parents) > len(prevouts):
        raise ValueError("excess parent data")
    expected_parents = {item.txid for item in tx.inputs}
    opened = {}
    for material in parents:
        parent, _ = material.open(chain)
        if parent.txid_wire() not in expected_parents or parent.txid_wire() in opened:
            raise ValueError("extraneous or duplicate parent data")
        at = (material.inclusion.height, material.inclusion.index)
        spending_at = (payment.inclusion.height, payment.inclusion.index)
        if at >= spending_at:
            raise ValueError("parent must precede payment in the adopted chain")
        opened[parent.txid_wire()] = parent, material.inclusion.height
    if set(opened) != expected_parents:
        raise ValueError("missing actual parent data")
    previous = {key: parent for key, (parent, _) in opened.items()}
    if any(not 0 <= item.vout < len(previous[item.txid].outputs) for item in tx.inputs):
        raise ValueError("actual input does not select an output")
    if authenticate(tx, previous) is not True:
        raise ValueError("unauthorized token creation or verifier")
    fee = sum(previous[item.txid].outputs[item.vout].value for item in tx.inputs) - sum(o.value for o in tx.outputs)
    if fee < 0:
        raise ValueError("invalid satoshi balance")
    validate_at_heights(tx, tuple(previous.values()), spend_height=payment.inclusion.height,
                        activation_height=activation_height,
                        utxo_heights=tuple(opened[item.txid][1] for item in tx.inputs))
    return VerifiedPayment(tx, Input(txid_wire, vout).outpoint(), depth, fee)

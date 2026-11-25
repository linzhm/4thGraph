"""Canonical BSV output identifying one redemption against the reserve."""
from dataclasses import dataclass

from shared.script import asm, push
from shared.transaction import Output, Transaction
from statement import fixed, uint

BURN_MARKER = asm("OP_0 OP_RETURN") + push(b"BSV/CCTP/burn/v1\x00")
PAYLOAD_SIZE = 32 + 4 + 20 + 8 + 8
SCRIPT_SIZE = len(BURN_MARKER) + 1 + PAYLOAD_SIZE


def burn_prefix(asset_id, reserve_domain):
    return BURN_MARKER + bytes([PAYLOAD_SIZE]) + fixed(asset_id, 32) + uint(reserve_domain, 4)


@dataclass(frozen=True)
class BurnReceipt:
    asset_id: bytes
    reserve_domain: int
    recipient: bytes
    quantity: int
    fee: int = 0

    def output(self) -> Output:
        recipient = fixed(self.recipient, 20)
        if not any(recipient):
            raise ValueError("empty redemption recipient")
        quantity, fee = uint(self.quantity, 8), uint(self.fee, 8)
        if self.quantity <= self.fee:
            raise ValueError("redemption must pay a positive net quantity")
        return Output(0, burn_prefix(self.asset_id, self.reserve_domain) + recipient + quantity + fee)

    @classmethod
    def parse(cls, output: Output) -> "BurnReceipt":
        script = output.script
        if not script.startswith(BURN_MARKER) or len(script) != SCRIPT_SIZE:
            raise ValueError("invalid burn receipt")
        data = script[len(BURN_MARKER) + 1:]
        receipt = cls(data[:32], int.from_bytes(data[32:36], "little"),
                      data[36:56], int.from_bytes(data[56:64], "little"),
                      int.from_bytes(data[64:72], "little"))
        if receipt.output() != output:
            raise ValueError("noncanonical burn receipt")
        return receipt


def read_burn(tx: Transaction, vout: int, asset) -> BurnReceipt:
    """Decode a specified vout. Consensus and provenance need independent validation."""
    if type(vout) is not int or not 0 <= vout < len(tx.outputs):
        raise ValueError("invalid burn vout")
    receipt = BurnReceipt.parse(tx.outputs[vout])
    if receipt.asset_id != asset.asset_id() or receipt.reserve_domain != asset.reserve_domain:
        raise ValueError("wrong asset or destination domain")
    return receipt

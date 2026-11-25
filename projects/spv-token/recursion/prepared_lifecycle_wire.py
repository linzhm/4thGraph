"""Wire encoding of the Two-Slot Lifecycle profile."""

from dataclasses import dataclass

from burn_receipt import SCRIPT_SIZE as BURN_SCRIPT_SIZE
from covenant_backtrace import PROOF_BYTES, PROOF_FIELDS
from settlement_checkpoint import CLAIM_BYTES
from shared.script import asm, push
from shared.transaction import Output
from statement import fixed, uint
from transfer import COMPACT_SCRIPTCODE as BINDING_CODE, verifier_input_script_hash

PROFILE = "prepared-lifecycle"
DOMAIN = b"BSV/CCTP/prepared-lifecycle/v1\0"
TOKEN = b"BSV/CCTP/lifecycle-token/v1\0"
EVENT = asm("OP_0 OP_RETURN") + push(b"BSV/CCTP/lifecycle-deposit/v1\0")
STATE_BYTES = 50
BLANK, ACTIVE, FROZEN, ISSUANCE = range(4)
MINT, TRANSFER, FREEZE, UNFREEZE, BURN = range(5)
COMPACT_CODE = asm("OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK") + BINDING_CODE
CONTEXT_BYTES = 157 + len(COMPACT_CODE)
BODY_BYTES = 2 + 2 * STATE_BYTES + 66 + 20 + 16 + 32
AUTH_BYTES = 2 * 71
TOKEN_HEAD = push(TOKEN) + asm("OP_DROP") + bytes([STATE_BYTES])
TOKEN_GUARD = (asm("OP_DROP OP_DEPTH OP_3 OP_NUMEQUALVERIFY")
               + verifier_input_script_hash() + b"\x20")
TOKEN_END = asm("OP_EQUAL")
TOKEN_TEMPLATE = TOKEN_HEAD + bytes(STATE_BYTES) + TOKEN_GUARD + bytes(32) + TOKEN_END
TOKEN_BYTES = len(TOKEN_TEMPLATE)
NULL_OUTPUT = Output(0, asm("OP_0 OP_RETURN") + push(bytes(TOKEN_BYTES - 5)))
NO_BURN = Output(0, asm("OP_0 OP_RETURN") + push(bytes(BURN_SCRIPT_SIZE - 4)))

REMAINDER = PROOF_FIELDS * (1 + PROOF_BYTES) + sum(
    len(push(bytes(width))) for width in (AUTH_BYTES, BODY_BYTES, 2 * CLAIM_BYTES, 32, 144, CONTEXT_BYTES))
HOLDER_BYTES = sum(len(push(bytes(width))) for width in (847, 144, 157 + TOKEN_BYTES))
OUTPUT_START = 1 + REMAINDER + 4 + 2 * (36 + 3 + HOLDER_BYTES + 4)
OUTPUT_WIDTHS = (TOKEN_BYTES, TOKEN_BYTES, BURN_SCRIPT_SIZE, len(EVENT) + 33)
SUFFIX_BYTES = OUTPUT_START + 1 + sum(8 + (3 if width >= 253 else 1) + width for width in OUTPUT_WIDTHS) + 4


@dataclass(frozen=True)
class State:
    kind: int = BLANK
    units: int = 0
    nonce: int = 0
    owner: bytes = bytes(33)

    def encode(self):
        if self.kind not in (BLANK, ACTIVE, FROZEN, ISSUANCE):
            raise ValueError("invalid lifecycle state kind")
        if self.kind == BLANK and (self.units or self.nonce or any(self.owner)):
            raise ValueError("blank slot must have zero state")
        if self.kind in (ACTIVE, FROZEN) and (not self.units or self.nonce or self.owner[:1] not in (b"\x02", b"\x03")):
            raise ValueError("invalid token state")
        if self.kind == ISSUANCE and any(self.owner):
            raise ValueError("invalid issuance state")
        return uint(self.kind, 1) + uint(self.units, 8) + uint(self.nonce, 8) + fixed(self.owner, 33)

    @classmethod
    def parse(cls, wire):
        fixed(wire, STATE_BYTES)
        state = cls(wire[0], int.from_bytes(wire[1:9], "little"), int.from_bytes(wire[9:17], "little"), wire[17:])
        if state.encode() != wire:
            raise ValueError("noncanonical lifecycle state")
        return state

    def output(self, policy):
        wire = self.encode()
        if self.kind == BLANK:
            return NULL_OUTPUT
        return Output(1_000, TOKEN_HEAD + wire + TOKEN_GUARD + fixed(policy, 32) + TOKEN_END)


def event_output(event):
    return Output(0, EVENT + push(fixed(event, 32)))


def read_state(output, policy):
    start = len(TOKEN_HEAD)
    state = State.parse(output.script[start:start + STATE_BYTES])
    if not state.kind or state.output(policy) != output:
        raise ValueError("different token policy or lifecycle state")
    return state

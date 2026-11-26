"""Lower constraints on the amount of a PELS successor."""

from dataclasses import dataclass

from compiler import SourceCompiler, required
from shared.script import asm, number, push
from shared.transaction import amount


@dataclass(frozen=True)
class FeeConstraint:
    minimum: int
    maximum: int

    def __post_init__(self):
        if not 0 <= self.minimum <= self.maximum <= 2_100_000_000_000_000:
            raise ValueError("expected ordered fee bounds within the satoshi amount range")

    @property
    def takes_witness(self):
        return self.minimum != self.maximum

    def require(self, fee):
        if not self.minimum <= fee <= self.maximum:
            raise ValueError(f"fee must be in [{self.minimum}, {self.maximum}] sat")
        return fee

    def lower_amount(self):
        """Consume the prevout amount and, for an interval, the fee below the state."""
        finish = asm("OP_SUB OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY OP_8 OP_NUM2BIN")
        if not self.takes_witness:
            return asm("OP_BIN2NUM") + number(self.minimum) + finish
        # Input: fee, state, scriptCode, amount. Bring the fee next to the amount.
        check = (asm("OP_3 OP_ROLL OP_DUP") + number(self.minimum) + number(self.maximum + 1)
                 + asm("OP_WITHIN OP_VERIFY OP_SWAP OP_BIN2NUM OP_SWAP"))
        return check + finish

    def witness_prefix(self, previous, successor):
        return number(previous - successor) if self.takes_witness else b""


@dataclass(frozen=True)
class WitnessAmount:
    """Take the successor amount as canonical transaction bytes from the witness."""

    takes_witness = True

    @staticmethod
    def lower_amount():
        # Input: next amount, state, scriptCode, authenticated previous amount.
        return asm("OP_DROP OP_ROT OP_SIZE OP_8 OP_NUMEQUALVERIFY")

    @staticmethod
    def witness_prefix(previous, successor):
        return push(amount(successor))


DEFAULT_FEE = FeeConstraint(1_000, 1_000)


class PelsSource(SourceCompiler):
    """Read the amount declaration alongside the existing typed Forth transition."""

    def __init__(self, source, *, source_path=None):
        self.amount_rule = DEFAULT_FEE
        self.amount_declaration = None
        super().__init__(source, source_path=source_path)

    def declaration(self, token):
        if token.name not in ("pels-fee:", "pels-amount:"):
            return super().declaration(token)
        if self.amount_declaration is not None:
            raise token.error("duplicate PELS successor amount declaration")
        self.amount_declaration = token
        if token.name == "pels-amount:":
            mode = required(self.tokens, token, "'witness'")
            if mode.name != "witness":
                raise mode.error("expected 'witness' after pels-amount:")
            end = required(self.tokens, token, "';'")
            if end.name != ";":
                raise end.error("expected ';' after the amount source")
            self.amount_rule = WitnessAmount()
            return
        lower = required(self.tokens, token, "minimum fee")
        upper = required(self.tokens, token, "maximum fee")
        end = required(self.tokens, token, "';'")
        if end.name != ";":
            raise end.error("expected ';' after the fee bounds")
        for bound in (lower, upper):
            if not bound.text.isascii() or not bound.text.isdecimal() or len(bound.text) > 16:
                raise bound.error("expected a decimal satoshi amount")
        try:
            self.amount_rule = FeeConstraint(int(lower.text), int(upper.text))
        except ValueError as error:
            raise token.error(str(error)) from error

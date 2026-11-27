"""Wire layout and canonical field values for bounded BN254 R1CS assignments."""

from dataclasses import dataclass
from hashlib import sha256
import json

FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def scalar(value):
    if type(value) is int:
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 77:
        return int(value)
    raise ValueError("expected an integer field element")


@dataclass(frozen=True)
class VerificationKey:
    signals: int
    constraints: tuple
    sha256: str
    outputs: int

    @property
    def current_wire(self):
        return self.outputs + 1

    @property
    def binding_wires(self):
        return self.current_wire + 1, self.current_wire + 2

    @classmethod
    def load(cls, raw):
        document = json.loads(raw)
        signals = document["nVars"]
        outputs = document["nOutputs"]
        if (document["prime"] != str(FIELD) or document["useCustomGates"]
                or type(outputs) is not int or outputs not in (1, 2)
                or (document["nPubInputs"], document["nPrvInputs"]) != (3, 0)
                or type(signals) is not int or not outputs + 4 <= signals <= 256):
            raise ValueError("expected a bounded BN254 R1CS with one or two outputs and three public inputs")
        constraints = document["constraints"]
        if not 1 <= len(constraints) <= 256 or len(constraints) != document["nConstraints"]:
            raise ValueError("invalid R1CS constraint count")

        def terms(linear):
            combined = []
            for wire, value in linear.items():
                index, coefficient = scalar(wire), scalar(value)
                if not 0 <= index < signals or str(index) != wire or not 0 <= coefficient < FIELD:
                    raise ValueError("invalid wire or coefficient in verification data")
                if coefficient:
                    combined.append((index, coefficient))
            return tuple(sorted(combined))

        normalized = []
        for constraint in constraints:
            left, right, result = constraint
            normalized.append((terms(left), terms(right), terms(result)))
        return cls(signals, tuple(normalized), sha256(raw).hexdigest(), outputs)

    def assignment(self, raw):
        values = tuple(map(scalar, json.loads(raw)))
        if len(values) != self.signals or values[0] != 1 or any(not 0 <= value < FIELD for value in values):
            raise ValueError("assignment must have canonical field values with wire zero equal to one")
        return values

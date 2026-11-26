"""Compile a transparent R1CS assignment verifier and its Forth successor policy."""

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from circuit_backend import select_circuit
from compiler import MAX_EXPANSION, PROJECT_NAME, PROJECT_VERSION, SourceCompiler, evaluate
from lowering import BASELINE, OPTIMIZATIONS, compile_word
from protocol import (
    BINDING_CODE, DEFAULT_TARGET, FLAG, OUTPUTS_HASH, ROOT_VALUE, TARGETS, TERMINAL_VALUE,
    begin, build_artifact, check_field, copy_preimage, finish, is_compressed_public_key, p2pk,
    single_input, validate_u32,
)
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, hash256, preimage_forkid
from wordsets import U32

FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
NEXT, ROUTE = 1, 2
LIMB_BYTES = 16
STATE_WIDTH = 5
STATE_PREFIX = asm("OP_0 OP_RETURN") + bytes([STATE_WIDTH])


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


def pick(depth):
    if depth < 2:
        return asm(("OP_DUP", "OP_OVER")[depth])
    return number(depth) + asm("OP_PICK")


class AssignmentScript:
    """Wire zero is implicit. Other wires stay under a shared field modulus."""

    def __init__(self, key, *, compact):
        self.key = key
        self.size = key.signals - 1
        self.compact = compact

    def wire(self, index, extra=0):
        return asm("OP_1") if index == 0 else pick(self.size - index + 1 + extra)

    def validate(self):
        code = asm("OP_DEPTH") + number(self.size) + asm("OP_NUMEQUALVERIFY") + number(FIELD)
        for index in range(1, self.size + 1):
            code += (self.wire(index) + asm("OP_DUP OP_DUP OP_BIN2NUM OP_EQUALVERIFY OP_0 OP_2 OP_PICK")
                     + asm("OP_WITHIN OP_VERIFY"))
        return code

    def linear(self, terms, extra):
        code = bytearray()
        if not terms or not self.compact:
            code.extend(asm("OP_0"))
        for index, (wire, coefficient) in enumerate(terms):
            has_sum = not self.compact or index > 0
            code.extend(self.wire(wire, extra + int(has_sum)))
            if self.compact and coefficient == FIELD - 1:
                code.extend(asm("OP_NEGATE"))
            elif not self.compact or coefficient != 1:
                # Signed residues preserve the equation modulo the field.
                signed = coefficient - FIELD if self.compact and coefficient > FIELD // 2 else coefficient
                code.extend(number(signed) + asm("OP_MUL"))
            if has_sum:
                code.extend(asm("OP_ADD"))
        return bytes(code)

    def constraint(self, left, right, result):
        if self.compact and (not left or not right):
            code = self.linear(result, 0)
        else:
            code = self.linear(left, 0) + self.linear(right, 1) + asm("OP_MUL")
            if result or not self.compact:
                code += self.linear(result, 1) + asm("OP_SUB")
        return code + asm("OP_OVER OP_MOD OP_0 OP_NUMEQUALVERIFY")

    def binding(self):
        code = copy_preimage() + asm("OP_HASH256") + number(LIMB_BYTES) + asm("OP_SPLIT")
        for index, extra in zip(reversed(self.key.binding_wires), (2, 1), strict=True):
            code += (self.wire(index, extra) + number(LIMB_BYTES + 1) + asm("OP_NUM2BIN")
                     + number(LIMB_BYTES) + asm("OP_SPLIT") + push(b"\0")
                     + asm("OP_EQUALVERIFY OP_EQUALVERIFY"))
        return code

    def cleanup(self):
        size = self.size + 1
        return asm("OP_2DROP") * (size // 2) + asm("OP_DROP") * (size % 2)


class StateContract:
    def __init__(self, source, current, keys, *, target=DEFAULT_TARGET, entries=None, terminal_value=TERMINAL_VALUE,
                 program=None, source_path=None):
        if type(current) is not int or not 0 <= current < U32:
            raise ValueError("committed current state must be u32")
        if any(not is_compressed_public_key(keys.get(role)) for role in ("review", "settle")):
            raise ValueError("proof contract requires review and settle public keys")
        if keys["review"] == keys["settle"]:
            raise ValueError("terminal scripts must be distinct")
        if type(terminal_value) is not int or not 0 < terminal_value < ROOT_VALUE:
            raise ValueError("terminal amount must be positive and leave a spend fee")
        if program is None:
            frontend = SourceCompiler(source.decode(), source_path=source_path)
            if frontend.relation:
                raise ValueError("relation: requires a generated circuit and the verification planner")
            if entries is not None or frontend.workflow_input is not None or frontend.stages:
                program = select_circuit(frontend, entries)
            else:
                route = frontend.words.get("decide")
        elif entries is not None:
            raise ValueError("circuit entries were already resolved")
        self.circuit = program
        if program is not None:
            route = program.route
        if route is None or (route.takes, route.gives) != (("u32",), ("route",)):
            raise ValueError("proof policy requires 'decide' with effect u32 -- route")
        self.target = target
        self.versions, _ = TARGETS[target]
        self.version = self.versions[-1]
        self.current, self.route = current, route
        self.terminals = tuple(Output(terminal_value, p2pk(keys[role])) for role in ("review", "settle"))

    def check_successor(self):
        # Consume the verified next state and route and check both outputs.
        prefix = Output(0, STATE_PREFIX + bytes(STATE_WIDTH)).serialize()[:-STATE_WIDTH]
        return (asm("OP_IF") + push(self.terminals[1].serialize()) + asm("OP_ELSE")
                + push(self.terminals[0].serialize()) + asm("OP_ENDIF OP_SWAP")
                + number(STATE_WIDTH) + asm("OP_NUM2BIN") + push(prefix)
                + asm("OP_SWAP OP_CAT OP_CAT OP_HASH256") + check_field(OUTPUTS_HASH))

    def unsigned(self, parent, next_state, *, version=None):
        if not parent.outputs or parent.outputs[0] != self.root or type(next_state) is not int or not 0 <= next_state < U32:
            raise ValueError("invalid deployment or next state")
        version = self.version if version is None else version
        if type(version) is not int or version not in self.versions:
            raise ValueError("proof spend version is outside the build target")
        route, = evaluate(self.route, next_state)
        state = Output(0, STATE_PREFIX + next_state.to_bytes(STATE_WIDTH, "little"))
        return Transaction((Input(parent.txid_wire(), 0),), (self.terminals[route], state), version=version)

    @staticmethod
    def binding_preimage(tx):
        return preimage_forkid(tx, 0, ROOT_VALUE, BINDING_CODE, FLAG)

    def public_binding(self, tx):
        digest = hash256(self.binding_preimage(tx))
        return tuple(int.from_bytes(digest[start:start + LIMB_BYTES], "little") for start in (0, LIMB_BYTES))


class ProofContract(StateContract):
    def __init__(self, source, key, current, keys, *, target=DEFAULT_TARGET, optimization=BASELINE, entries=None,
                 terminal_value=TERMINAL_VALUE, program=None, max_expansion=MAX_EXPANSION, source_path=None):
        super().__init__(source, current, keys, target=target, entries=entries, terminal_value=terminal_value,
                         program=program, source_path=source_path)
        self.key = key
        word = compile_word(self.route, optimization, max_expansion=max_expansion)
        plain = self.compile(word.script, compact=False)
        compact = self.compile(word.script, compact=True) if optimization == "stack" else plain
        self.root = Output(ROOT_VALUE, compact if len(compact) < len(plain) else plain)
        self.optimization = optimization
        self.rewrites = list(word.describe()["rewrites"])
        if self.root.script != plain:
            self.rewrites.append({"rule": "r1cs-linear-combination", "script_bytes": [len(plain), len(compact)],
                                  "basis": "zero products, unit coefficients and centered residues modulo BN254"})

    def compile(self, route, *, compact):
        layout = AssignmentScript(self.key, compact=compact)
        code = bytearray(begin(self.versions) + single_input() + layout.validate())
        code.extend(layout.wire(self.key.current_wire) + number(self.current) + asm("OP_NUMEQUALVERIFY"))
        code.extend(layout.binding())
        for terms in self.key.constraints:
            code.extend(layout.constraint(*terms))
        code.extend(layout.wire(NEXT) + validate_u32() + asm("OP_DUP") + route)
        if self.key.outputs == 2:
            code.extend(layout.wire(ROUTE, 2) + asm("OP_OVER OP_NUMEQUALVERIFY"))
        code.extend(self.check_successor())
        code.extend(layout.cleanup() + finish())
        return bytes(code)

    def describe(self):
        spec = {
            "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "schema_version": 1,
            "proof": "transparent-r1cs-assignment", "verification_key_sha256": self.key.sha256,
            "binding": "HASH256 of the authenticated ForkID ALL preimage",
            "signals": self.key.signals, "constraints": len(self.key.constraints), "current": self.current,
            "public_outputs": ("next", "route") if self.key.outputs == 2 else ("next",),
            "target": self.target, "optimization": self.optimization, "rewrites": self.rewrites,
            "deploy_output": {"satoshis": ROOT_VALUE, "script_hex": self.root.script.hex()},
        }
        if self.circuit:
            spec["circuit"] = self.circuit.describe()
        return spec

    def seal(self, tx, assignment):
        if len(assignment) != self.key.signals or assignment[0] != 1 or any(
            type(value) is not int or not 0 <= value < FIELD for value in assignment
        ):
            raise ValueError("invalid transparent proof assignment")
        proof = b"".join(map(number, assignment[1:]))
        return tx.with_script(0, proof + push(self.binding_preimage(tx)))


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("source", type=Path)
    cli.add_argument("--entries", nargs=2, metavar=("TRANSITION", "ROUTE"), help="select two Forth words")
    cli.add_argument("--verification-key", type=Path, required=True)
    cli.add_argument("--keys", type=Path, required=True, help="role-to-compressed-public-key hex JSON")
    cli.add_argument("--current", type=int, required=True)
    cli.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET)
    cli.add_argument("--optimize", choices=OPTIMIZATIONS, default=BASELINE)
    args = cli.parse_args()
    try:
        source = args.source.read_bytes()
        key = VerificationKey.load(args.verification_key.read_bytes())
        keys = {role: bytes.fromhex(public) for role, public in json.loads(args.keys.read_bytes()).items()}
        contract = ProofContract(source, key, args.current, keys, target=args.target, optimization=args.optimize,
                                 entries=args.entries, source_path=args.source)
        print(json.dumps(build_artifact(contract.describe(), source), indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        cli.error(str(error))


if __name__ == "__main__":
    main()

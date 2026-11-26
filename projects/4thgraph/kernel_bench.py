"""Compare matched projective arithmetic kernels in fully verified regtest spends."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from random import Random
import sys
from types import SimpleNamespace

from compiler import PROJECT_NAME
from protocol import ROOT_VALUE, UTXO
from replay import Replay, SOURCE
from shared.benchmark_validation import ACTIVATION_HEIGHT, CONTEXT_PIN, Node, chain_metadata
from shared.evaluate import evaluate
from shared.script import asm, encode_num, number
from shared.transaction import Input, Output, Transaction
from stack_schedule import Graph
from wordsets import push_value

R1_REFERENCE = Path(__file__).resolve().parents[1] / "p2pkh-r1" / "reference"
SCHNORR_REVISION = "a1f4485ba84bbc2211be75316626f9ac76636197"
SCHNORR_FILES = {
    "schnorr_script.py": "1c29f5297d5c85b70916307a7cc8a3d46f2e2c1bea506461c4e521c82ec63925",
    "bip340.py": "103f797c6402e94e50423b9adfa312acdadb3798ef1c2cb9763f057865461cc2",
}


def operand(graph, slots, value):
    return graph.define(number(value)) if isinstance(value, int) else slots[value]


def curve_kernel(inputs, assignments):
    from curve_compiler import Expression, OUTPUTS

    graph = Graph(len(inputs) + 2)
    slots = dict(zip(("field", "b3", *inputs), graph.inputs, strict=True))

    def expression(value):
        if isinstance(value, Expression):
            return graph.define(asm("OP_" + value.op), tuple(expression(arg) for arg in value.args))
        return operand(graph, slots, value)

    for name, formula in assignments:
        result = expression(formula)
        if name in OUTPUTS:
            result = graph.define(asm("OP_MOD"), (result, slots["field"]))
        slots[name] = result
    return graph.emit(tuple(slots[name] for name in ("field", "b3", *OUTPUTS)))


class RecordedSum:
    """Record the existing BIP340 point-sum generator with explicit field input."""

    def __init__(self, names):
        inputs = ("field", *names.split())
        self.graph = Graph(len(inputs))
        self.values = dict(zip(inputs, self.graph.inputs, strict=True))

    def op(self, name, opcode, *operands):
        args = tuple(operand(self.graph, self.values, item) for item in operands)
        self.values[name] = self.graph.define(asm(opcode), args)
        return name

    def field_value(self, name, value):
        self.op(name, "OP_MOD", value, "field")

    def keep(self, *names):
        self.code = self.graph.emit(tuple(self.values[name] for name in ("field", *names)))


def kernels(schnorr_path):
    for filename, digest in SCHNORR_FILES.items():
        if sha256((schnorr_path / filename).read_bytes()).hexdigest() != digest:
            raise ValueError(f"{filename} differs from Schnorr revision {SCHNORR_REVISION}")
    sys.path.insert(0, str(R1_REFERENCE))
    sys.path.insert(0, str(schnorr_path))
    import curve_compiler as r1
    import schnorr_script as schnorr
    from bip340 import FIELD as schnorr_field

    baseline = r1.curve_blocks(scheduled=True)
    double = (asm("OP_DUP OP_0NOTEQUAL OP_IF")
              + curve_kernel(r1.DOUBLE_INPUTS, r1._ordered(r1.DOUBLE, r1._DOUBLE_ORDER))
              + asm("OP_ENDIF"))
    old_sum = schnorr._point_sum()
    saved = schnorr._Program
    try:
        schnorr._Program = RecordedSum
        schnorr._point_sum.cache_clear()
        new_sum = schnorr._point_sum()
    finally:
        schnorr._Program = saved
        schnorr._point_sum.cache_clear()
    return {
        "P256-add": ((r1.FIELD, r1.B3), 6, baseline["ADD_POINTS"],
                     curve_kernel(r1.ADD_INPUTS, r1._ordered(r1.ADD, r1._ADD_ORDER))),
        "P256-double": ((r1.FIELD, r1.B3), 3, baseline["DOUBLE_POINT"], double),
        "BIP340-loop-point-sum": ((schnorr_field,), 6, old_sum, new_sum),
    }


def vectors(constants, arity):
    field = constants[0]
    yield (*constants, *([0] * arity))
    yield (*constants, *([field - 1] * arity))
    yield (*constants, *([-(field - 1)] * arity))
    rng = Random(11704)
    for _ in range(150):
        yield (*constants, *(rng.randrange(1 - field, field) for _ in range(arity)))


def compare(reference, candidate, inputs):
    stack = list(map(encode_num, inputs))
    expected, alt = evaluate(reference, stack)
    actual, candidate_alt = evaluate(candidate, stack)
    if alt or candidate_alt or actual != expected:
        raise ValueError("matched kernel changed its result")
    return expected


def run(replay, bootstrap, slot, code, inputs, expected):
    # Fixture commits the entire expected stack including the field constants.
    check = b"".join(push_value(entry) + asm("OP_EQUALVERIFY") for entry in reversed(expected))
    lock = code + check + asm("OP_1")
    funded, deployment = replay.deploy(SimpleNamespace(root=Output(ROOT_VALUE, lock), version=2), bootstrap, slot)
    utxo = UTXO(funded, 0)
    tx = Transaction((Input(funded.txid_wire(), 0, b"".join(map(number, inputs))),),
                     (Output(ROOT_VALUE - 10_000, SOURCE.output.script),))
    spend = replay.record(tx, (utxo,))
    return {"kernel_bytes": len(code), "deploy": deployment, "spend": spend}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schnorr-reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError(f"unexpected chain-gang build: {engine}")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) != 0 or node.call("getconnectioncount", []):
        raise ValueError("kernel benchmarks require an empty peerless regtest")
    replay = Replay(node, 7, "chronicle-v2", int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", ACTIVATION_HEIGHT)))
    pairs = kernels(args.schnorr_reference)
    bootstrap = replay.fund(len(pairs) * 2)
    report = {}
    for i, (name, (constants, arity, reference, candidate)) in enumerate(pairs.items()):
        for count, inputs in enumerate(vectors(constants, arity), 1):
            expected = compare(reference, candidate, inputs)
        report[name] = {"development_vectors": count,
                        "reference": run(replay, bootstrap, 2 * i, reference, inputs, expected),
                        "stack": run(replay, bootstrap, 2 * i + 1, candidate, inputs, expected)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"project": PROJECT_NAME, "schnorr_revision": SCHNORR_REVISION,
                                      "chain_gang": engine, "kernels": report}, indent=2) + "\n")


if __name__ == "__main__":
    main()

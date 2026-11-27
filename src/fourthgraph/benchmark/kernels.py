"""Compare matched projective arithmetic kernels in fully verified regtest spends."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from fourthgraph._paths import CHECKOUT
from random import Random
import sys
from types import SimpleNamespace

from fourthgraph.compiler.source import PROJECT_NAME, PROJECT_VERSION
from fourthgraph.workflow.protocol import ROOT_VALUE, UTXO
from fourthgraph.replay.workflow import Replay, SOURCE
from fourthgraph.benchmark.validation import ACTIVATION_HEIGHT, CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.script import asm, encode_num, number
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.stack_schedule import Graph
from fourthgraph.compiler.wordsets import push_value

R1_REFERENCE = CHECKOUT / "projects/p2pkh-r1/reference"
SCHNORR_REVISION = "a1f4485ba84bbc2211be75316626f9ac76636197"
SCHNORR_FILES = {
    "schnorr_script.py": "1c29f5297d5c85b70916307a7cc8a3d46f2e2c1bea506461c4e521c82ec63925",
    "bip340.py": "103f797c6402e94e50423b9adfa312acdadb3798ef1c2cb9763f057865461cc2",
}


def operand(graph, slots, value):
    return graph.define(number(value)) if isinstance(value, int) else slots[value]


def curve_kernel(inputs, assignments, *, compact=False):
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
    return graph.emit(tuple(slots[name] for name in ("field", "b3", *OUTPUTS)), compact=compact)


class RecordedSum:
    """Record the existing BIP340 point-sum generator with explicit field input."""

    compact = False

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
        self.code = self.graph.emit(tuple(self.values[name] for name in ("field", *names)), compact=self.compact)


class CompactSum(RecordedSum):
    compact = True


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
    def double(compact):
        return (asm("OP_DUP OP_0NOTEQUAL OP_IF")
                + curve_kernel(r1.DOUBLE_INPUTS, r1._ordered(r1.DOUBLE, r1._DOUBLE_ORDER), compact=compact)
                + asm("OP_ENDIF"))

    def add(compact):
        return curve_kernel(r1.ADD_INPUTS, r1._ordered(r1.ADD, r1._ADD_ORDER), compact=compact)

    old_sum = schnorr._point_sum()
    saved = schnorr._Program
    try:
        schnorr._Program = RecordedSum
        schnorr._point_sum.cache_clear()
        new_sum = schnorr._point_sum()
        schnorr._Program = CompactSum
        schnorr._point_sum.cache_clear()
        compact_sum = schnorr._point_sum()
    finally:
        schnorr._Program = saved
        schnorr._point_sum.cache_clear()
    return {
        "P256-add": ((r1.FIELD, r1.B3), 6, {"reference": baseline["ADD_POINTS"], "stack": add(False), "compact": add(True)}),
        "P256-double": ((r1.FIELD, r1.B3), 3,
                        {"reference": baseline["DOUBLE_POINT"], "stack": double(False), "compact": double(True)}),
        "BIP340-loop-point-sum": ((schnorr_field,), 6, {"reference": old_sum, "stack": new_sum, "compact": compact_sum}),
    }


def vectors(constants, arity):
    field = constants[0]
    yield (*constants, *([0] * arity))
    yield (*constants, *([field - 1] * arity))
    yield (*constants, *([-(field - 1)] * arity))
    rng = Random(11704)
    for _ in range(150):
        yield (*constants, *(rng.randrange(1 - field, field) for _ in range(arity)))


def run(replay, bootstrap, slot, code, inputs, expected, failures):
    # Fixture commits the entire expected stack including the field constants.
    check = b"".join(push_value(entry) + asm("OP_EQUALVERIFY") for entry in reversed(expected))
    lock = code + check + asm("OP_1")
    funded, deployment = replay.deploy(SimpleNamespace(root=Output(ROOT_VALUE, lock), version=2), bootstrap, slot)
    utxo = UTXO(funded, 0)
    tx = Transaction((Input(funded.txid_wire(), 0, b"".join(map(number, inputs))),),
                     (Output(ROOT_VALUE - 10_000, SOURCE.output.script),))
    controls = {}
    for label, values in failures.items():
        invalid = tx.with_script(0, b"".join(map(number, values)))
        controls[label] = replay.record(invalid, (utxo,), expected=False)
    spend = replay.record(tx, (utxo,))
    return {"kernel_bytes": len(code), "deploy": deployment, "spend": spend, "controls": controls}


def measure_vectors(variants, constants, arity):
    peaks = {name: dict(main=0, alt=0, combined=0) for name in variants}
    for count, inputs in enumerate(vectors(constants, arity), 1):
        stacks = {}
        for name, code in variants.items():
            def observe(main, alt):
                main_bytes, alt_bytes = sum(map(len, main)), sum(map(len, alt))
                for key, size in zip(peaks[name], (main_bytes, alt_bytes, main_bytes + alt_bytes), strict=True):
                    peaks[name][key] = max(peaks[name][key], size)

            stack, alt = evaluate(code, list(map(encode_num, inputs)), observe_stack=observe)
            if alt:
                raise ValueError(f"{name} left an alternate stack")
            stacks[name] = stack
        expected = stacks["reference"]
        if any(stack != expected for stack in stacks.values()):
            raise ValueError(f"kernel results differ on vector {count}")
    return count, inputs, expected, peaks


def failure_vectors(constants, arity):
    coordinates = (1,) * arity
    return {"zero_modulus": (0, *constants[1:], *coordinates), "missing_inputs": constants}


def require_failure(code, inputs):
    try:
        evaluate(code, list(map(encode_num, inputs)))
    except ScriptError:
        return
    raise ValueError("kernel accepted a negative test vector")


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
    bootstrap = replay.fund(sum(len(variants) for _, _, variants in pairs.values()))
    report, slot = {}, 0
    for name, (constants, arity, variants) in pairs.items():
        count, inputs, expected, peaks = measure_vectors(variants, constants, arity)
        failures = failure_vectors(constants, arity)
        report[name] = {"development_vectors": count, "failure_vectors": list(failures)}
        for version, code in variants.items():
            for values in failures.values():
                require_failure(code, values)
            report[name][version] = {
                **run(replay, bootstrap, slot, code, inputs, expected, failures), "kernel_peak_payload_bytes": peaks[version],
            }
            slot += 1
        report[name]["selected"] = "compact" if len(variants["compact"]) < len(variants["stack"]) else "stack"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "schnorr_revision": SCHNORR_REVISION,
        "r1_curve_compiler_sha256": sha256((R1_REFERENCE / "curve_compiler.py").read_bytes()).hexdigest(),
        "bsv_node_version": node.version, "chain_gang": engine, "bootstrap_raw": bootstrap.serialize().hex(),
        "optimization": {
            "rule": "stack-local-operand-scheduling",
            "assumptions": "acyclic total arithmetic under canonical ScriptNums and nonzero field for OP_MOD",
            "selection_metric": "script_bytes",
            "validation": "same reference inputs, exact stack values, full spends and negative controls in both engines",
        },
        "kernels": report,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

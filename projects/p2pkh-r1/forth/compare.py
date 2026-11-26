"""Compare the Forth kernels with the existing P-256 reference."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

import curve_compiler
from compile_p256 import ENTRIES, SOURCE, build, identity
from fourthgraph.benchmark.kernels import failure_vectors, measure_vectors, require_failure, run
from fourthgraph.replay.workflow import Replay
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import decode_num, encode_num

G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    1,
)
INFINITY = (0, 1, 0)
TWICE_G = (
    0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978,
    0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1,
)
CONSTANTS = (curve_compiler.FIELD, curve_compiler.B3)


def curve_vectors(arity):
    if arity == 3:
        return ((G, TWICE_G), (INFINITY, None))
    opposite = (G[0], CONSTANTS[0] - G[1], 1)
    return ((G + G, TWICE_G), (G + opposite, None), (G + INFINITY, G[:2]),
            (INFINITY + G, G[:2]), (INFINITY + INFINITY, None))


def check_points(variants, arity):
    field, _ = CONSTANTS
    cases = curve_vectors(arity)
    for coordinates, expected in cases:
        initial = list(map(encode_num, (*CONSTANTS, *coordinates)))
        for name, code in variants.items():
            stack, alt = evaluate(code, initial)
            p, b3, x, y, z = map(decode_num, stack)
            inverse = pow(z, -1, field) if z % field else None
            point = (x * inverse % field, y * inverse % field) if inverse is not None else None
            if alt or (p, b3) != CONSTANTS or point != expected:
                raise ValueError(f"{name} returned the wrong point for {coordinates}")
    return len(cases)


def compare(source, *, regtest=False):
    reference = curve_compiler.curve_blocks(scheduled=True)
    kernels = build(source)
    report = {**identity(source), "reference_sha256": sha256(Path(curve_compiler.__file__).read_bytes()).hexdigest()}
    replay = None
    if regtest:
        engine = chain_metadata()
        if engine["commit"] != CONTEXT_PIN:
            raise ValueError("use the chain-gang version pinned in tools/requirements-chronicle.txt")
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        if node.call("getblockcount", []) or node.call("getconnectioncount", []):
            raise ValueError("use a fresh peerless regtest")
        replay = Replay(node, 7, "chronicle-v2", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
        bootstrap = replay.fund(2 * len(kernels))
        report.update(bsv_node_version=node.version, chain_gang=engine, bootstrap_raw=bootstrap.serialize().hex())

    rows = {}
    slot = 0
    for name, (reference_entry, arity) in ENTRIES.items():
        variants = {"reference": reference[reference_entry], "forth": kernels[name]}
        count, inputs, expected, peaks = measure_vectors(variants, CONSTANTS, arity)
        failures = failure_vectors(CONSTANTS, arity)
        row = {"arithmetic_vectors": count, "curve_vectors": check_points(variants, arity),
               "failure_vectors": list(failures), "delta_bytes": len(variants["forth"]) - len(variants["reference"])}
        for variant, code in variants.items():
            for values in failures.values():
                require_failure(code, values)
            row[variant] = {"kernel_bytes": len(code), "kernel_sha256": sha256(code).hexdigest(),
                            "kernel_peak_payload_bytes": peaks[variant]}
            if replay:
                row[variant].update(run(replay, bootstrap, slot, code, inputs, expected, failures))
            slot += 1
        rows[name] = row
    return {**report, "kernels": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--regtest", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(compare(args.source.read_bytes(), regtest=args.regtest), indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
    else:
        print(report, end="")


if __name__ == "__main__":
    main()

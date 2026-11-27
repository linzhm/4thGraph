"""Compile and replay a fixed, high-level BIP340 payment experiment."""
import argparse
from collections import Counter
from dataclasses import dataclass, replace
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
import os
from statistics import median
import sys
from time import perf_counter_ns

from coincurve import PrivateKey

from fourthgraph import PROJECT_VERSION
from fourthgraph.benchmark.cases import native_coin, seed
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata, chain_verdict, stack_profile
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, decode_num, encode_num, number
from fourthgraph.bsv.spend_authorization import prepare_authorization
from fourthgraph.bsv.transaction import CHRONICLE, Input, Output, Transaction
from fourthgraph.compiler.lowering import compile_word
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.script_formula import FORMULA_PASSES
from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.compiler.wordsets import Primitive, cell_comparison, script_word

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
sys.path.insert(0, str(PROJECT / "reference"))

from bip340 import ORDER, lift_x, to_bytes
from schnorr_script import (_contract, authorization_codes, compile_unlock, compiled_template,
                            lock_for_owner, owner_hash, verifier)
from test_schnorr import MODES, detached_unlock, malformed_witnesses, official_vectors


@dataclass(frozen=True)
class Plan:
    name: str
    runtime: str
    passes: tuple[str, ...] | None
    rules: tuple[str, ...] = ()


def plans():
    yield Plan("source-baseline", "baseline", ())
    yield Plan("control-only", "stack", ())
    yield Plan("formula-only", "baseline", None)
    yield Plan("compiler-auto", "stack", None)
    yield Plan("safe-and-auto", "safe", None)
    for count in range(1, len(FORMULA_PASSES) + 1):
        for passes in combinations(FORMULA_PASSES, count):
            if "search" not in passes or "stack" in passes:
                yield Plan("+".join(passes), "stack", passes)
    yield Plan("ordered-rules", "stack", ("share", "stack", "search"),
               ("double-as-add", "elide-redundant-remainder"))


def digest(code):
    return sha256(code).hexdigest()


def fragment(code, inputs, outputs):
    """Expose a compiled numeric formula to the typed Script frontend."""
    def run(*values):
        result, _ = evaluate(code, list(map(encode_num, values)))
        return tuple(map(decode_num, result))

    return Primitive(("script-int",) * inputs, ("script-int",) * outputs, code, run,
                     "bounded Forth formula")


def compile_candidate(plan, *, trace=False, source=None, entry="reference-bip340",
                      extra_vocabulary=None, source_prefix="", link_vocabulary=None):
    started = perf_counter_ns()
    arithmetic = ScriptBuilder.from_file(
        HERE / "arithmetic.fth", optimize=plan.passes is None,
        formula_passes=plan.passes, experimental_rules=plan.rules, trace_formulas=trace,
    )
    library = ScriptBuilder("REQUIRE stdlib/bip340.fth\n")
    vocabulary = {}
    kernels = {}
    for name, formula in arithmetic.formula_ir.items():
        code = arithmetic.emit(name, b"")
        vocabulary[name] = fragment(code, formula.input_count, len(formula.returns))
        kernels[name] = {**arithmetic.formulas[name], "bytes": len(code), "sha256": digest(code)}
    # The existing library supplies the byte-to-unsigned-number boundary and the
    # four public secp256k1 constants. Group arithmetic comes from arithmetic.fth.
    vocabulary.update({
        "uint256be": script_word("bytes", "script-int", library.emit("script-uint256be", b""),
                                 lambda data: int.from_bytes(data, "big"), repeatable=True,
                                 fixed_width_code=(32, library.emit("script-uint256be-compact", b""))),
        "int<": cell_comparison("script-int script-int", asm("OP_LESSTHAN"), lambda a, b: a < b),
        "int=": cell_comparison("script-int script-int", asm("OP_NUMEQUAL"), lambda a, b: a == b),
        "scalar-threshold": script_word("", "script-int", number(1 << 255), lambda: 1 << 255),
    })
    for name, word in (("field-prime", "secp256k1-field"), ("group-order", "secp256k1-order"),
                       ("generator-x", "secp256k1-gx"), ("generator-y", "secp256k1-gy")):
        literal = library.emit(word, b"")
        (value,), _ = evaluate(literal)
        vocabulary[name] = script_word("", "script-int", literal, lambda value=value: decode_num(value), repeatable=True)
    if extra_vocabulary is not None:
        vocabulary.update(extra_vocabulary(library))
    if link_vocabulary is not None:
        vocabulary.update(link_vocabulary(vocabulary, plan.runtime))
    source = source or HERE / "verifier.fth"
    frontend = SourceCompiler(source_prefix + source.read_text(), vocabulary=vocabulary, source_path=source)
    compiled = compile_word(frontend.words[entry], plan.runtime)
    detached = library.emit("bip340-check-witness-depth", b"") + compiled.script
    owner_prefix = _contract().emit("schnorr-check-owner", b"", bytes(20))
    binding = _contract().emit("bind-current-input", asm("OP_FROMALTSTACK"))
    lock = owner_prefix + detached + asm("OP_VERIFY") + binding
    costs = {"kernels": kernels, "runtime_rewrites": dict(Counter(rule.rule for rule in compiled.rewrites))}
    if trace:
        costs["trace"] = arithmetic.formula_stack_plans
    return detached, lock, costs, (perf_counter_ns() - started) / 1_000_000


def detached_cases(detached):
    parent = Transaction((Input(seed("high-level/detached"), 0),), (Output(10_000, detached),))

    def spend(witness):
        return Transaction((Input(parent.txid_wire(), 0, witness),), (Output(9_900, asm("OP_1")),))

    for row in official_vectors():
        x, message, signature = (bytes.fromhex(row[key]) for key in ("public key", "message", "signature"))
        expected = row["verification result"] == "TRUE"
        yield "BIP340/" + row["index"], spend(detached_unlock(message, x, signature)), (parent,), expected
        if row["index"] == "0":
            for name, witness in malformed_witnesses(x, message, signature):
                yield name, spend(witness), (parent,), False


def payment_case(template, owner_offset, sighash, shape):
    def owned_output(label, value):
        # Public keys and auxiliary randomness for deterministic benchmark fixtures only.
        scalar = int.from_bytes(seed("high-level/" + label), "big")
        key = PrivateKey.from_int(1 + scalar % (ORDER - 1))
        owner = owner_hash(key.public_key_xonly.format())
        lock = template[:owner_offset] + owner + template[owner_offset + len(owner):]
        return Output(value, lock), key

    shape_inputs, shape_outputs = shape
    pairs = [owned_output(f"parent/{i}", 10_000) for i in range(shape_inputs)]
    parents = tuple(Transaction((Input(seed(f"high-level/funding/{i}"), 0),), (output,))
                    for i, (output, _) in enumerate(pairs))
    amount = (shape_inputs * 10_000 - 100) // shape_outputs
    outputs = (tuple(owned_output(f"recipient/{i}", amount)[0] for i in range(shape_outputs))
               if shape_inputs == 2 else (native_coin("high-level/exit", amount).output,))
    tx = Transaction(tuple(Input(parent.txid_wire(), 0) for parent in parents), outputs,
                     version=2 if sighash & CHRONICLE else 1)
    ordinary, companion = authorization_codes()
    for i, (previous, key) in enumerate(pairs):
        auth = prepare_authorization(tx, i, previous.value, sighash, ordinary_code=ordinary,
                                     companion_code=companion)
        x = key.public_key_xonly.format()
        signature = key.sign_schnorr(auth.checked_digest(), aux_randomness=bytes(32))
        witness = compile_unlock(auth.preimage, auth.companion, x, to_bytes(lift_x(x)[1]),
                                 signature, to_bytes(lift_x(signature[:32])[1]))
        if evaluate(witness)[0][0] != auth.preimage:
            raise ValueError("the witness must push the complete literal preimage")
        tx = tx.with_script(i, witness)
    return tx, parents


def engine_verdicts(node, tx, parents):
    return chain_verdict(tx, parents), node.verdicts(tx, parents, timeout_us=1_000_000)


def require_verdict(node, label, tx, parents, expected):
    chain, bsv = engine_verdicts(node, tx, parents)
    if chain != expected or bsv != [expected] * len(parents):
        raise ValueError(f"{label}: expected {expected}, got chain-gang={chain}, BSV Node={bsv}")


def replay(node, detached, lock, owner_offset):
    cases = list(detached_cases(detached))
    for label, tx, parents, expected in cases:
        require_verdict(node, label, tx, parents, expected)

    transactions = {}
    timings = {"detached": next((tx, parents) for _, tx, parents, valid in cases if valid)}
    for shape, flags in (((2, 2), MODES), ((1, 1), (0x41, 0x61))):
        for flag in flags:
            label = f"{shape[0]}x{shape[1]}/{flag:02x}"
            tx, parents = payment_case(lock, owner_offset, flag, shape)
            require_verdict(node, label, tx, parents, True)
            require_verdict(node, label + "/changed locktime", replace(tx, locktime=1), parents, False)
            if flag in (0x41, 0x61):
                transactions[label] = {
                    "bytes": len(tx.serialize()), "txid": tx.txid(),
                    "unlock_bytes": [len(item.script) for item in tx.inputs],
                    "output_lock_bytes": [len(item.script) for item in tx.outputs],
                    "input_zero_stack_peak": stack_profile(parents[0].outputs[0].script, tx.inputs[0].script),
                }
                if shape == (1, 1):
                    timings[label] = (tx, parents)
    return {"detached_cases": len(cases), "positive_payments": len(MODES) + 2,
            "changed_locktime_rejections": len(MODES) + 2, "transactions": transactions}, timings


def measure(node, variants, samples):
    measurements = {name: {} for name in variants}
    names = list(variants)
    for workload in variants[names[0]]:
        for engine, check in (("chain_gang", chain_verdict),
                              ("bsv_node_rpc", lambda tx, parents: node.verdicts(tx, parents,
                                                                               timeout_us=1_000_000) == [True])):
            elapsed = {name: [] for name in names}
            for index in range(2 + samples):
                offset = index % len(names)
                for name in names[offset:] + names[:offset]:
                    start = perf_counter_ns()
                    valid = check(*variants[name][workload])
                    duration = perf_counter_ns() - start
                    if not valid:
                        raise ValueError(f"timed verification failed: {name}/{workload}/{engine}")
                    if index >= 2:
                        elapsed[name].append(duration)
            for name in names:
                values = measurements[name].setdefault(workload, {})
                values[engine] = round(median(elapsed[name]) / 1_000_000, 3)
    return measurements


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--output", required=True, type=Path)
    args.add_argument("--samples", type=int, default=12, help="alternating timed runs per finalist and workload")
    options = args.parse_args()
    if options.samples < 1:
        args.error("--samples must be positive")
    if not os.environ.get("REGTEST_URL"):
        args.error("run through tools/verify_node.sh --profile raised")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    metadata = chain_metadata()
    if metadata["commit"] != CONTEXT_PIN:
        args.error("install the project requirements to use pinned chain-gang")
    options.output.mkdir(parents=True, exist_ok=True)
    released_lock, owner_offset = compiled_template(bytes(20))
    if released_lock != lock_for_owner(bytes(20), version="v0.17.0"):
        raise ValueError("the manual comparison must reproduce frozen v0.17.0")
    builds = {"manual-v0.17.0": (verifier(), released_lock, {})}
    for plan in plans():
        detached, lock, costs, elapsed = compile_candidate(plan)
        print(f"{plan.name}: {len(lock):,} lock bytes", flush=True)
        builds[plan.name] = (detached, lock, {"runtime": plan.runtime, "formula_passes": plan.passes,
                                             "ordered_rules": plan.rules, "compile_ms": round(elapsed, 3), **costs})

    by_hash, rows, timing_cases = {}, {}, {}
    for name, (detached, lock, costs) in builds.items():
        artifact = {"lock_bytes": len(lock), "lock_sha256": digest(lock),
                    "verifier_bytes": len(detached), "verifier_sha256": digest(detached)}
        identity = (artifact["lock_sha256"], artifact["verifier_sha256"])
        first = by_hash.get(identity)
        if first is None:
            receipt, timing_cases[name] = replay(node, detached, lock, owner_offset)
            print(f"{name}: both engines passed", flush=True)
            by_hash[identity] = name
            for kind, code in (("verifier", detached), ("lock", lock)):
                (options.output / f"{name}-{kind}.hex").write_text(code.hex() + "\n")
        else:
            receipt = {"byte_identical_to": first}
            timing_cases[name] = timing_cases[first]
        rows[name] = {**artifact, **costs, "verification": receipt}

    winner = min((name for name in rows if name != "manual-v0.17.0"),
                 key=lambda name: rows[name]["lock_bytes"])
    finalist_names = ("manual-v0.17.0", "source-baseline", winner)
    timings = measure(node, {name: timing_cases[name] for name in finalist_names}, options.samples)
    report = {"compiler": PROJECT_VERSION, "chain_gang": metadata, "bsv_node": node.version,
              "source_sha256": {path.name: digest(path.read_bytes()) for path in
                                (HERE / "arithmetic.fth", HERE / "verifier.fth", Path(__file__))},
              "owner_hash160_offset": owner_offset, "winner": winner, "candidates": rows,
              "timings": {"per_workload_per_engine": options.samples, "median_ms": timings}}
    winning_plan = next(plan for plan in plans() if plan.name == winner)
    detached, lock, traced, _ = compile_candidate(winning_plan, trace=True)
    if (digest(detached), digest(lock)) != (rows[winner]["verifier_sha256"], rows[winner]["lock_sha256"]):
        raise ValueError("the traced replay did not reproduce the winner")
    (options.output / "winner-trace.json").write_text(json.dumps(traced["trace"], indent=2) + "\n")
    (options.output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

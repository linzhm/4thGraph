"""Search complete Groth16 locks compiled from one high-level Forth source."""

import argparse
from dataclasses import replace
import json
from hashlib import sha256
from itertools import product
from pathlib import Path

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.transaction import blob
from fourthgraph.compiler.formula_experiment import enumerate_orders
from fourthgraph.replay.bls12381_verifier import FIXTURE, SOURCES, fixture, witness_controls
from fourthgraph.verification.bls12381.affine_witness import (
    MILLER_KERNELS, MILLER_REDUCTIONS, MSM_STRATEGIES, MSM_TABLES,
)
from fourthgraph.verification.bls12381.build import (
    G1_REDUCTIONS, MAX_G1_Z_BATCH, RESIDUE_ASSOCIATIONS, SCRIPT_ERAS, ArithmeticPlan, ForthVerifier,
)
from fourthgraph.verification.bls12381.field import FP2_RULES, fp2_kernel
from fourthgraph.verification.bls12381.verifier import public_packet


SOURCE = Path(__file__).with_name("verifier.fth")
PROJECT = SOURCE.parents[2]
LAYOUT = "affine-inline"


def verifier(key, source, source_path, era, plan=None):
    return ForthVerifier(key, source, script_era=era, witness_layout=LAYOUT,
                         entry="verify-proof", source_path=source_path, plan=plan)


def verify_vectors(lock, witnesses, controls, *, profile_stack=False):
    peak = 0

    def observe(main, alt):
        nonlocal peak
        peak = max(peak, sum(map(len, main)) + sum(map(len, alt)))

    def succeeds(witness, observer=None):
        try:
            stack, alt = evaluate(witness)
            return not alt and evaluate(lock, stack, observe_stack=observer) == ([b"\x01"], [])
        except ScriptError:
            return False

    accepted = sum(succeeds(witness, observe if profile_stack else None) for witness in witnesses)
    rejected = sum(not succeeds(control) for control in controls)
    if accepted != len(witnesses) or rejected != len(controls):
        raise ValueError(f"verifier accepted {accepted}/{len(witnesses)} valid proofs and rejected "
                         f"{rejected}/{len(controls)} controls")
    return {"accepted": accepted, "rejected": rejected}, peak


def measure(compiler, witnesses, packets, *, profile_stack=False):
    diagnostics = {}
    lock = compiler.lower(compiler.sources(SOURCES), compact=True, diagnostics=diagnostics)
    artifact = compiler.artifact(SOURCES, None, lock)
    controls = tuple(control for index in range(len(witnesses))
                     for control in witness_controls(witnesses, packets, index, artifact["proof_packet_bytes"],
                                                     layout=LAYOUT).values())
    verdicts, peak = verify_vectors(lock, witnesses, controls, profile_stack=profile_stack)
    result = {
        "lock_bytes": len(lock),
        "path_bytes": len(blob(lock)) + max(len(blob(witness)) for witness in witnesses),
        "script_sha256": artifact["script_sha256"],
        "artifact_sha256": artifact["artifact_sha256"],
        "witness_bytes": [len(witness) for witness in witnesses],
        "witness_sha256": [sha256(witness).hexdigest() for witness in witnesses],
        "msm_slope_count": artifact["msm_slope_count"],
        "local_verdicts": verdicts,
        **diagnostics,
    }
    if profile_stack:
        result["fixture_stack_payload_bytes"] = peak
    if compiler.plan is not None:
        result["plan"] = artifact["arithmetic_plan"]
    return result, artifact


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--era", choices=SCRIPT_ERAS, help="restrict the search to one Script era")
    cli.add_argument("--source", type=Path, default=SOURCE, help="Forth source revision to compile")
    cli.add_argument("--residue-association", choices=RESIDUE_ASSOCIATIONS,
                     help="hold the residue multiplication order fixed while comparing Fp2 lowerings")
    cli.add_argument("--msm", choices=MSM_STRATEGIES, help="restrict the MSM witness and lowering strategy")
    cli.add_argument("--msm-table", choices=MSM_TABLES, help="restrict the MSM point table representation")
    cli.add_argument("--miller-reductions", choices=MILLER_REDUCTIONS, help="restrict the Miller reduction schedule")
    cli.add_argument("--miller-kernel", choices=MILLER_KERNELS, help="restrict the affine Miller arithmetic")
    g1 = cli.add_mutually_exclusive_group()
    g1.add_argument("--try-paired-g1-doubles", action="store_true",
                    help="also compare deferring reductions across two consecutive G1 doublings")
    g1.add_argument("--g1-reductions", choices=G1_REDUCTIONS, help="restrict the G1 reduction schedule")
    cli.add_argument("--g1-z-batch", type=int, action="append", choices=range(1, MAX_G1_Z_BATCH + 1),
                     help="compare this G1 Z batch size, repeat for multiple sizes (default: 1)")
    cli.add_argument("--try-compact-booleans", action="store_true",
                     help="also compare folding nonzero tests into numeric boolean operations")
    cli.add_argument("--max-fixture-stack-bytes", type=int,
                     help="limit the measured stack payload on the two valid development proofs")
    cli.add_argument("--fp2-selection", choices=("uniform", "callsite"), help="restrict the Fp2 kernel selection")
    cli.add_argument("--output", type=Path, default=PROJECT / "workspace/build/high-level")
    args = cli.parse_args()
    stack_limit = args.max_fixture_stack_bytes
    if stack_limit is not None and stack_limit <= 0:
        cli.error("--max-fixture-stack-bytes must be positive")
    profile_stack = stack_limit is not None
    args.output.mkdir(parents=True, exist_ok=True)

    key, cases = fixture()
    source = args.source.read_bytes()
    reference_path = PROJECT / "verifier.fth"
    reference_source = reference_path.read_bytes()
    formula, kernel_digest = fp2_kernel(())
    associations = (args.residue_association,) if args.residue_association else RESIDUE_ASSOCIATIONS
    plans = []
    if args.fp2_selection != "callsite":
        plans.extend(ArithmeticPlan(rules, association) for rules, association
                     in product(enumerate_orders(formula), associations))
    if args.fp2_selection != "uniform":
        plans.extend(ArithmeticPlan(FP2_RULES, association, "callsite") for association in associations)
    strategies = (args.msm,) if args.msm else MSM_STRATEGIES
    tables = (args.msm_table,) if args.msm_table else MSM_TABLES
    reductions = (args.miller_reductions,) if args.miller_reductions else MILLER_REDUCTIONS
    kernels = (args.miller_kernel,) if args.miller_kernel else MILLER_KERNELS
    plans = [replace(plan, msm=msm, msm_table=table, miller_reductions=reduction, miller_kernel=kernel)
             for msm, table, reduction, kernel, plan in product(strategies, tables, reductions, kernels, plans)
             if msm == "signed-radix4" or table == "points"]
    if not plans:
        cli.error("doubling-slope tables require signed radix-4 MSM")
    g1_reductions = G1_REDUCTIONS if args.try_paired_g1_doubles else (args.g1_reductions or G1_REDUCTIONS[0],)
    z_batches = tuple(dict.fromkeys(args.g1_z_batch or (1,)))
    booleans = (False, True) if args.try_compact_booleans else (False,)
    plans = [replace(plan, g1_reductions=g1, g1_z_batch=z, compact_booleans=compact)
             for g1, z, compact, plan in product(g1_reductions, z_batches, booleans, plans)]
    packets = [public_packet(SOURCES, signals) for signals, _ in cases]
    report = {
        "objective": "path-bytes",
        "witness_layout": LAYOUT,
        "same_source_sha256": sha256(source).hexdigest(),
        "fixture_sha256": sha256(FIXTURE.read_bytes()).hexdigest(),
        "fp2_source_sha256": kernel_digest,
        "eras": {},
    }
    if profile_stack:
        report["max_fixture_stack_bytes"] = stack_limit
    selected_locks = {}
    for era in (args.era,) if args.era else SCRIPT_ERAS:
        reference = verifier(key, reference_source, reference_path, era)
        witnesses = [reference.witness(signals, proof, sources=SOURCES) for signals, proof in cases]
        witness_sets = {reference.msm: witnesses}
        reference_row, _ = measure(reference, witnesses, packets, profile_stack=profile_stack)
        candidates = []
        for plan in plans:
            compiler = verifier(key, source, args.source, era, plan)
            if plan.msm not in witness_sets:
                witness_sets[plan.msm] = [compiler.witness(signals, proof, sources=SOURCES)
                                         for signals, proof in cases]
            result, artifact = measure(compiler, witness_sets[plan.msm], packets, profile_stack=profile_stack)
            candidates.append((result, artifact))
            print(era, plan, result["lock_bytes"], flush=True)
        eligible = ([row for row in candidates if row[0]["fixture_stack_payload_bytes"] <= stack_limit]
                    if profile_stack else candidates)
        if not eligible:
            cli.error(f"{era}: no candidate meets the measured fixture stack limit of {stack_limit} bytes")
        winner, lock = min(eligible, key=lambda row: row[0]["path_bytes"])
        report["eras"][era] = {
            "reference": reference_row,
            "witness_bytes": winner["witness_bytes"],
            "witness_sha256": winner["witness_sha256"],
            "candidates": [result for result, _ in candidates],
            "selected_plan": winner["plan"],
        }
        selected_locks[era] = lock
    for era, lock in selected_locks.items():
        write_json(args.output / f"{era}-plan.json", report["eras"][era]["selected_plan"])
        write_json(args.output / f"{era}-lock.json", lock)
    write_json(args.output / "search.json", report)


if __name__ == "__main__":
    main()

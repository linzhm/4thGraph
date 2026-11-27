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
from fourthgraph.verification.bls12381.affine_witness import MSM_STRATEGIES, MSM_TABLES
from fourthgraph.verification.bls12381.build import (
    RESIDUE_ASSOCIATIONS, SCRIPT_ERAS, ArithmeticPlan, ForthVerifier,
)
from fourthgraph.verification.bls12381.field import FP2_RULES, fp2_kernel
from fourthgraph.verification.bls12381.verifier import public_packet


SOURCE = Path(__file__).with_name("verifier.fth")
PROJECT = SOURCE.parents[2]
LAYOUT = "affine-inline"


def verifier(key, source, source_path, era, plan=None):
    return ForthVerifier(key, source, script_era=era, witness_layout=LAYOUT,
                         entry="verify-proof", source_path=source_path, plan=plan)


def verify_vectors(lock, witnesses, controls):
    def succeeds(witness):
        try:
            stack, alt = evaluate(witness)
            return not alt and evaluate(lock, stack) == ([b"\x01"], [])
        except ScriptError:
            return False

    accepted = sum(succeeds(witness) for witness in witnesses)
    rejected = sum(not succeeds(control) for control in controls)
    if accepted != len(witnesses) or rejected != len(controls):
        raise ValueError(f"verifier accepted {accepted}/{len(witnesses)} valid proofs and rejected "
                         f"{rejected}/{len(controls)} controls")
    return {"accepted": accepted, "rejected": rejected}


def measure(compiler, witnesses, packets):
    diagnostics = {}
    lock = compiler.lower(compiler.sources(SOURCES), compact=True, diagnostics=diagnostics)
    artifact = compiler.artifact(SOURCES, None, lock)
    controls = tuple(control for index in range(len(witnesses))
                     for control in witness_controls(witnesses, packets, index, artifact["proof_packet_bytes"],
                                                     layout=LAYOUT).values())
    result = {
        "lock_bytes": len(lock),
        "path_bytes": len(blob(lock)) + max(len(blob(witness)) for witness in witnesses),
        "script_sha256": artifact["script_sha256"],
        "artifact_sha256": artifact["artifact_sha256"],
        "witness_bytes": [len(witness) for witness in witnesses],
        "witness_sha256": [sha256(witness).hexdigest() for witness in witnesses],
        "msm_slope_count": artifact["msm_slope_count"],
        "local_verdicts": verify_vectors(lock, witnesses, controls),
        **diagnostics,
    }
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
    cli.add_argument("--output", type=Path, default=PROJECT / "workspace/build/high-level")
    args = cli.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    key, cases = fixture()
    source = args.source.read_bytes()
    reference_path = PROJECT / "verifier.fth"
    reference_source = reference_path.read_bytes()
    formula, kernel_digest = fp2_kernel(())
    associations = (args.residue_association,) if args.residue_association else RESIDUE_ASSOCIATIONS
    plans = [ArithmeticPlan(rules, association) for rules, association
             in product(enumerate_orders(formula), associations)]
    plans.extend(ArithmeticPlan(FP2_RULES, association, "callsite") for association in associations)
    strategies = (args.msm,) if args.msm else MSM_STRATEGIES
    tables = (args.msm_table,) if args.msm_table else MSM_TABLES
    plans = [replace(plan, msm=msm, msm_table=table) for msm, table, plan in product(strategies, tables, plans)
             if msm == "signed-radix4" or table == "points"]
    if not plans:
        cli.error("doubling-slope tables require signed radix-4 MSM")
    packets = [public_packet(SOURCES, signals) for signals, _ in cases]
    report = {
        "objective": "path-bytes",
        "witness_layout": LAYOUT,
        "same_source_sha256": sha256(source).hexdigest(),
        "fixture_sha256": sha256(FIXTURE.read_bytes()).hexdigest(),
        "fp2_source_sha256": kernel_digest,
        "eras": {},
    }
    selected_locks = {}
    for era in (args.era,) if args.era else SCRIPT_ERAS:
        reference = verifier(key, reference_source, reference_path, era)
        witnesses = [reference.witness(signals, proof, sources=SOURCES) for signals, proof in cases]
        witness_sets = {reference.msm: witnesses}
        reference_row, _ = measure(reference, witnesses, packets)
        candidates = []
        for plan in plans:
            compiler = verifier(key, source, args.source, era, plan)
            if plan.msm not in witness_sets:
                witness_sets[plan.msm] = [compiler.witness(signals, proof, sources=SOURCES)
                                         for signals, proof in cases]
            result, artifact = measure(compiler, witness_sets[plan.msm], packets)
            candidates.append((result, artifact))
            print(era, plan, result["lock_bytes"], flush=True)
        winner, lock = min(candidates, key=lambda row: row[0]["path_bytes"])
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

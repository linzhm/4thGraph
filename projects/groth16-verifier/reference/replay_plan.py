"""Rebuild the selected Groth16 v0.9.0 plan and optionally replay its funded spends."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from fourthgraph.bsv.transaction import Transaction, blob
from fourthgraph.verification.bls12381.build import ArithmeticPlan, ForthVerifier, SCRIPT_ERAS
from fourthgraph.verification.bls12381.verifier import input_sources, public_signals

PROJECT = Path(__file__).resolve().parents[1]
PLAN = PROJECT / "versions/v0.9.0/replay-plan.json"
FIXTURE = PROJECT.parent / "proof-counter/versions/v0.1.0/bls12381-counter.json"
INPUTS = PROJECT / "versions/v0.1.0/input-sources.json"


def check(name, actual, expected):
    if actual != expected:
        raise ValueError(f"{name} mismatch: expected {expected}, got {actual}")


def digest(raw):
    return sha256(raw).hexdigest()


def build(plan, era):
    source_path = PROJECT / plan["source"]
    source, inputs, fixture_bytes = source_path.read_bytes(), INPUTS.read_bytes(), FIXTURE.read_bytes()
    check("Forth source SHA-256", digest(source), plan["source_sha256"])
    check("public input configuration SHA-256", digest(inputs), plan["input_sources_sha256"])
    check("fixture SHA-256", digest(fixture_bytes), plan["fixture_sha256"])
    fixture = json.loads(fixture_bytes)
    key = json.dumps(fixture["verification_key"])
    check("verification key SHA-256", digest(key.encode()), plan["verification_key_sha256"])
    sources = input_sources(inputs)
    target = plan["script_eras"][era]
    verifier = ForthVerifier(key, source, witness_layout=plan["witness_layout"], script_era=era,
                             entry=plan["entry"], source_path=source_path,
                             plan=ArithmeticPlan(**target["arithmetic_plan"]))
    check("stack schedule", plan["stack_schedule"], "compact")
    lock = verifier.compile(sources, compact=True)
    artifact = verifier.artifact(sources, None, lock, compact=True)
    check("lock bytes", len(lock), target["lock_bytes"])
    check("lock SHA-256", digest(lock), target["script_sha256"])
    check("artifact SHA-256", artifact["artifact_sha256"], target["artifact_sha256"])

    witnesses = {}
    for name in ("wrap", "other"):
        case = fixture[name]
        signals = public_signals(json.dumps(case["public"]))
        witness = verifier.witness(signals, json.dumps(case["proof"]), sources=sources)
        expected = plan["witnesses"][name]
        check(f"{name} witness bytes", len(witness), expected["bytes"])
        check(f"{name} witness SHA-256", digest(witness), expected["sha256"])
        check(f"{name} path bytes", len(blob(lock)) + len(blob(witness)), target["path_bytes"])
        witnesses[name] = witness
    return artifact, witnesses


def replay_funded(plan, era, lock, witnesses, plan_digest):
    target = plan["script_eras"][era]
    activation = target["chronicle_activation_height"]
    check("Chronicle activation height", os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT"), str(activation))
    with TemporaryDirectory() as temporary:
        arithmetic = Path(temporary) / "arithmetic.json"
        arithmetic.write_text(json.dumps(target["arithmetic_plan"]), encoding="utf-8")
        report_path = Path(temporary) / "replay.json"
        subprocess.run([
            sys.executable, "-m", "fourthgraph.replay.bls12381_verifier",
            "--source", str(PROJECT / plan["source"]), "--entry", plan["entry"],
            "--witness-layout", plan["witness_layout"], "--script-era", era,
            "--tx-version", str(plan["transaction_version"]), "--arithmetic-plan", str(arithmetic),
            "--output", str(report_path),
        ], check=True)
        report = json.loads(report_path.read_bytes())

    check("funded replay artifact SHA-256", report["artifact"]["artifact_sha256"], target["artifact_sha256"])
    for (name, witness), row in zip(witnesses.items(), report["statements"], strict=True):
        deployment = Transaction.parse(bytes.fromhex(row["deployment_raw"]))
        spend = Transaction.parse(bytes.fromhex(row["spend"]["raw"]))
        check(f"{name} deployed lock", digest(deployment.outputs[0].script), digest(lock))
        check(f"{name} funded witness", digest(spend.inputs[0].script), digest(witness))
        check(f"{name} deployed Script era", row["deploy"]["height"] >= activation, era == "chronicle")
    report["replay_plan_sha256"] = plan_digest
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--script-era", choices=SCRIPT_ERAS, default="genesis")
    cli.add_argument("--funded", action="store_true", help="also run the funded replay in an isolated regtest")
    args = cli.parse_args()
    try:
        raw_plan = PLAN.read_bytes()
        plan = json.loads(raw_plan)
        artifact, witnesses = build(plan, args.script_era)
        report = (replay_funded(plan, args.script_era, bytes.fromhex(artifact["script_hex"]), witnesses, digest(raw_plan))
                  if args.funded else None)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        cli.error(str(error))

    output = PROJECT / "workspace/build/pinned-v0.9.0" / args.script_era
    output.mkdir(parents=True, exist_ok=True)
    (output / "lock.json").write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    for name, witness in witnesses.items():
        (output / f"{name}-witness.hex").write_text(witness.hex() + "\n", encoding="utf-8")
    if report is not None:
        (output / "replay.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()

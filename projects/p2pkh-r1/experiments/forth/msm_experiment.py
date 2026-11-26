"""Scan, test, build and compare bounded P-256 mul2 candidates for R1."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from time import perf_counter

from fixed_templates import read_compiled_template, read_otda_reconstruction
from fourthgraph.bsv.evaluate import evaluate
from msm_compiler import CALIBRATION, SOURCE, R1MSMCompiler, payment_estimates
from msm_lowering import verify_window
from replay_r1 import CONTEXT_PIN, MODES, Node, Replay, chain_metadata, matrix_check, replay_layout

OBJECTIVES = ("lock_bytes", "bip143-all", "otda-all", "otda-single")
# This fourth explicit candidate already appears in the previous comparison.
REFERENCE_TRIAL = "split-5"
FROZEN_BASELINE = "v0.6.0"


def elapsed(start):
    return round(perf_counter() - start, 6)


def objective(row, field, metric):
    values = row[field]
    return values["lock_bytes"] if metric == "lock_bytes" else values["payment_bytes"][metric]


def measure(payments, lock, pattern):
    return {
        "lock_bytes": len(lock.script), "otda_program_bytes": len(pattern.program),
        "payment_bytes": {mode: row["spend"]["bytes"] for mode, row in payments.items()},
        "payment_peak_stack_payload_bytes": {
            mode: row["spend"]["stack"]["combined_payload_bytes"] for mode, row in payments.items()
        },
        "unlock_bytes": {mode: row["unlock_bytes"] for mode, row in payments.items()},
    }


def estimated_cost(compiler, plan, program, lock, pattern):
    costs = compiler.local_cost(plan, program)
    size = len(compiler.prepare) + costs["window_bytes"] + len(compiler.finish(program.table_points))
    if size != len(lock.script):
        raise ValueError("counted window cost does not match the compiled lock")
    otda = len(pattern.program)
    # Heuristic only. Table slots and pending radix digits dominate the MSM;
    # reconstructed OTDA bytes dominate the two OTDA fixture modes.
    counts = plan.counts()
    digits = counts["g_lookups"] + counts["q_lookups"] + counts["joint_lookups"]
    bip143_peak = 99 * plan.table_points + 2 * digits + 400
    return {
        **costs, "lock_bytes": size, "otda_program_bytes": otda, "payment_bytes": payment_estimates(size, otda),
        "payment_peak_stack_payload_bytes": {
            "bip143-all": bip143_peak, "otda-all": max(bip143_peak, 4 * size + 400),
            "otda-single": max(bip143_peak, 2 * size + 400),
        },
    }


def local_build(compiler, plan, vectors):
    start = perf_counter()
    program = compiler.lower(plan)
    lower_seconds = elapsed(start)
    start = perf_counter()
    vector_count = verify_window(program, vectors)
    vector_seconds = elapsed(start)
    start = perf_counter()
    lock, pattern = compiler.link(program)
    estimate = estimated_cost(compiler, plan, program, lock, pattern)
    return (lock, pattern), {
        "status": "local-verified", "point_vectors": vector_count, "reconstruction_byte_match": True,
        "estimated": estimate, "lock_sha256": sha256(lock.script).hexdigest(),
        "otda_program_sha256": sha256(pattern.program).hexdigest(),
        "phase_seconds": {"lower": lower_seconds, "local_vectors": vector_seconds, "link": elapsed(start)},
    }


def frozen_build():
    start = perf_counter()
    directory = SOURCE.parents[2] / "template" / FROZEN_BASELINE
    layout = json.loads((directory / "layout.json").read_text(encoding="ascii"))
    if f"v{layout['template_version']}" != FROZEN_BASELINE:
        raise ValueError("R1 baseline layout has the wrong version")
    lock = read_compiled_template(directory, layout)
    _, program = read_otda_reconstruction(directory, layout["compressed_preimage"])
    pattern = lock.reconstruction(program)
    if evaluate(program) != (list(pattern.fixed_parts), []):
        raise ValueError("frozen OTDA reconstruction differs from the versioned lock")
    return (lock, pattern), {
        "status": "local-verified", "template_version": layout["template_version"],
        "construction": layout["construction"], "build_source": layout["build_source"],
        "reconstruction_byte_match": True, "estimated": layout["estimated"],
        "lock_sha256": layout["script_sha256"], "otda_program_sha256": layout["compressed_preimage"]["program_sha256"],
        "phase_seconds": {"load_and_check": elapsed(start)},
    }


def scan_proposal(scans):
    opportunities = [opportunity for scan in scans.values() for opportunity in scan["opportunities"]
                     if opportunity["id"] == "affine-g" and opportunity["try"]]
    return max(opportunities, key=lambda item: item["priority"])


def shortlist(rows, limit):
    names = [name for name, row in rows.items() if row["status"] == "local-verified"]
    leaders = [min(names, key=lambda name: objective(rows[name], "estimated", metric))
               for metric in OBJECTIVES] if names else []
    baseline = (FROZEN_BASELINE,) if FROZEN_BASELINE in names else ()
    selected = tuple(dict.fromkeys((*baseline, *leaders, *names)))[:limit]
    for name in names:
        if name not in selected:
            rows[name].update(status="local-only", reason="full-payment replay budget exhausted")
    return selected


def reference_rows(document):
    rows = document["layouts"] if "layouts" in document else document["candidates"]
    result = {}
    for name, candidate in rows.items():
        row = dict(candidate.get("measured", candidate))
        if "payment_bytes" in row:
            row["payment_bytes"] = {"bip143-all" if mode == "forkid-all" else mode: size
                                    for mode, size in row["payment_bytes"].items()}
        result[name] = row
    return result


def compare(args):
    start = perf_counter()
    compiler = R1MSMCompiler(args.source)
    scans = {}
    if args.workflow == "guided":
        scans = {name: compiler.scan(compiler.plan(name)) for name in CALIBRATION}
        proposal = scan_proposal(scans)
        default_candidates = (CALIBRATION[0], proposal["try"], *CALIBRATION[1:])
    else:
        proposal = None
        default_candidates = (*CALIBRATION, REFERENCE_TRIAL)
    names = tuple(dict.fromkeys(args.candidate or default_candidates))
    if FROZEN_BASELINE in names:
        names = (FROZEN_BASELINE, *(name for name in names if name != FROZEN_BASELINE))
    reference = {}
    if args.reference:
        raw = args.reference.read_bytes()
        reference = reference_rows(json.loads(raw))
    known = {*CALIBRATION, REFERENCE_TRIAL, FROZEN_BASELINE, *reference}
    rows, builds = {}, {}
    summary = {
        **compiler.source_identity, "workflow": args.workflow, "proposal": proposal, "scans": scans,
        "budget": {"local_candidates": args.budget, "full_candidates": args.full_budget,
                   "point_vectors_per_candidate": args.vectors, "timing_samples": args.samples,
                   "full_acceptance_matrix": args.matrix},
        "candidates": rows,
    }
    if args.reference:
        summary["reference_sha256"] = sha256(raw).hexdigest()
    times = {"frontend_and_scan_seconds": elapsed(start), "first_locally_verified_seconds": None,
             "first_novel_locally_verified_seconds": None, "first_dual_engine_seconds": None,
             "first_novel_dual_engine_seconds": None, "measured_decision_seconds": None}
    local_attempts = 0
    for name in names:
        try:
            plan = None if name == FROZEN_BASELINE else compiler.plan(name)
        except ValueError as error:
            rows[name] = {"status": "ineligible", "reason": str(error)}
            continue
        if local_attempts >= args.budget:
            rows[name] = {"status": "not-tested", "reason": "local candidate budget exhausted"}
            continue
        local_attempts += 1
        try:
            builds[name], rows[name] = (frozen_build() if name == FROZEN_BASELINE
                                        else local_build(compiler, plan, args.vectors))
            if times["first_locally_verified_seconds"] is None:
                times["first_locally_verified_seconds"] = elapsed(start)
            if name not in known and times["first_novel_locally_verified_seconds"] is None:
                times["first_novel_locally_verified_seconds"] = elapsed(start)
        except ValueError as error:
            rows[name] = {"status": "local-rejected", "reason": str(error)}

    evidence = {"payments": {}, "acceptance": {}}
    candidates = shortlist(rows, args.full_budget)
    if candidates:
        engine = chain_metadata()
        if engine["commit"] != CONTEXT_PIN:
            raise ValueError("use the pinned Chronicle-aware chain-gang")
        node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
        if node.call("getblockcount", []) or node.call("getconnectioncount", []):
            raise ValueError("use a fresh peerless regtest")
        runner = Replay(node, args.samples, "chronicle-v2", int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]))
        bootstrap = runner.fund(len(candidates) * len(MODES))
        evidence.update(bsv_node_version=node.version, chain_gang=engine, funding_parent_hex=bootstrap.serialize().hex(),
                        regtest_profile=os.environ["SCRIPT_LAB_REGTEST_PROFILE"])
        for index, name in enumerate(candidates):
            stage = perf_counter()
            lock, pattern = builds[name]
            try:
                payments = replay_layout(runner, bootstrap, index, lock, pattern)
                rows[name].update(status="verified", measured=measure(payments, lock, pattern))
                evidence["payments"][name] = payments
                if times["first_dual_engine_seconds"] is None:
                    times["first_dual_engine_seconds"] = elapsed(start)
                if name not in known and times["first_novel_dual_engine_seconds"] is None:
                    times["first_novel_dual_engine_seconds"] = elapsed(start)
            except ValueError as error:
                rows[name].update(status="payment-rejected", reason=str(error))
            rows[name]["phase_seconds"]["funded_replay"] = elapsed(stage)

        if args.matrix:
            for name in evidence["payments"]:
                stage = perf_counter()
                try:
                    evidence["acceptance"][name] = matrix_check(builds[name][0])
                except (AssertionError, ValueError) as error:
                    rows[name].update(status="matrix-rejected", reason=str(error))
                rows[name]["phase_seconds"]["acceptance_matrix"] = elapsed(stage)

    verified = [name for name, row in rows.items() if row["status"] == "verified"]
    controls = [name for name in verified if name in CALIBRATION]
    summary["selected"] = select(rows, verified)
    summary["calibration_selected"] = select(rows, controls)
    summary["calibration"] = {
        name: {field: rows[name]["measured"][field] == reference[name][field]
               for field in ("lock_bytes", "otda_program_bytes", "payment_bytes")
               if field in reference.get(name, {})}
        for name in controls
    }
    comparisons = [("split-5x4", "split-4"), ("joint-2", "split-5x4"),
                   ("split-4-affine-g", "split-4"), ("split-5x4-affine-g", "split-5x4")]
    if FROZEN_BASELINE in verified:
        comparisons.extend((name, FROZEN_BASELINE) for name in verified if name != FROZEN_BASELINE)
    summary["cost_differences"] = [
        cost_difference(rows, candidate, baseline)
        for candidate, baseline in comparisons
        if candidate in verified and baseline in verified
    ]
    summary["novel_candidates_verified"] = [
        name for name in verified if name not in known
    ]
    for name in verified:
        wins = [metric for metric, choice in summary["selected"].items() if choice == name]
        rows[name]["decision"] = {"selected_for": wins}
        if not wins:
            rows[name]["decision"]["reason"] = "verified; measured byte cost is higher for every objective"
    if verified:
        times["measured_decision_seconds"] = elapsed(start)
    summary["timing"] = times
    return summary, evidence


def select(rows, names):
    return {metric: min(names, key=lambda name: objective(rows[name], "measured", metric))
            for metric in OBJECTIVES} if names else {}


def cost_difference(rows, candidate, baseline):
    left, right = rows[candidate], rows[baseline]
    return {
        "candidate": candidate, "baseline": baseline,
        "lock_bytes": left["measured"]["lock_bytes"] - right["measured"]["lock_bytes"],
        "otda_program_bytes": left["measured"]["otda_program_bytes"] - right["measured"]["otda_program_bytes"],
        "window_sections_bytes": {
            section: size - right["estimated"]["window_sections_bytes"][section]
            for section, size in left["estimated"]["window_sections_bytes"].items()
        },
        "payment_bytes": {
            mode: objective(left, "measured", mode) - objective(right, "measured", mode) for mode in MODES
        },
    }


def markdown(report):
    labels = {"lock_bytes": "Lock bytes", "bip143-all": "BIP143 ALL",
              "otda-all": "OTDA ALL", "otda-single": "OTDA SINGLE"}
    lines = ["# R1 candidate comparison", "",
             "Each value is an estimate / measured result in bytes. Peak values cover both Script stacks.", "",
             "| Candidate | Status | Lock | BIP143 ALL | OTDA ALL | OTDA SINGLE | Peak stack (BIP143 ALL / OTDA ALL / OTDA SINGLE) |",
             "| --- | --- | ---: | ---: | ---: | ---: | --- |"]
    for name, row in report["candidates"].items():
        estimate, measured = row.get("estimated", {}), row.get("measured", {})
        pair = lambda first, second: f"{first:,} / {second:,}" if second is not None else f"{first:,} / —"
        lock = pair(estimate["lock_bytes"], measured.get("lock_bytes")) if estimate else "—"
        payments = [pair(estimate["payment_bytes"][mode], measured.get("payment_bytes", {}).get(mode))
                    for mode in MODES] if estimate else ["—"] * len(MODES)
        peaks = [pair(estimate["payment_peak_stack_payload_bytes"][mode],
                      measured.get("payment_peak_stack_payload_bytes", {}).get(mode))
                 for mode in MODES] if estimate else ["—"] * len(MODES)
        lines.append("| " + " | ".join([name.replace("|", r"\|"), row["status"], lock, *payments, ", ".join(peaks)]) + " |")
    lines.extend(["", "## Decisions", ""])
    for metric, name in report["selected"].items():
        cost = objective(report["candidates"][name], "measured", metric)
        lines.append(f"- **{labels[metric]}** selects `{name}` at {cost:,} B.")
    for name, row in report["candidates"].items():
        reason = row.get("reason") or row.get("decision", {}).get("reason")
        if reason:
            lines.append(f"- **{name}** {reason}.")
    for delta in report["cost_differences"]:
        sections = delta["window_sections_bytes"]
        lines.append(f"- `{delta['candidate']}` vs `{delta['baseline']}` changes table setup by "
                     f"{sections['table_setup']:+,} B, digit extraction by {sections['digit_extraction']:+,} B, "
                     f"the repeated window by {sections['window_loop']:+,} B and the OTDA reconstruction program by "
                     f"{delta['otda_program_bytes']:+,} B.")
    return "\n".join(lines) + "\n"


def scan_text(report):
    location = report["source"]
    lines = [f"{location['file']}:{location['line']}:{location['column']}  "
             f"{report['intrinsic']}  ({report['candidate']})", ""]
    for item in report["opportunities"]:
        lines.append(f"{item['id']}  {item['calls']} sites  |  try {item['try'] or 'unavailable'}")
        lines.extend(f"  proven  {fact}" for fact in item["proven"])
        lines.extend(f"  missing {fact}" for fact in item["missing"])
        if item["estimated"]:
            lines.append("  estimate " + ", ".join(f"{name}={value}" for name, value in item["estimated"].items()))
    return "\n".join(lines) + "\n"


def dump(value, output=None):
    raw = json.dumps(value, indent=2) + "\n"
    if output:
        output.write_text(raw)
    else:
        print(raw, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "local", "build", "compare"):
        command = sub.add_parser(name)
        command.add_argument("--source", type=Path, default=SOURCE)
        command.add_argument("--candidate", action="append" if name == "compare" else "store",
                             default=None if name == "compare" else "split-4",
                             help=(f"window construction or frozen {FROZEN_BASELINE} baseline; repeat to compare"
                                   if name == "compare" else "window construction"))
        command.add_argument("--output", type=Path)
        if name == "scan":
            command.add_argument("--format", choices=("text", "json"))
        if name != "scan":
            command.add_argument("--vectors", type=int, default=32)
        if name == "build":
            command.add_argument("--owner-hash160", type=bytes.fromhex, default=bytes(20))
        if name == "compare":
            command.add_argument("--workflow", choices=("guided", "explicit"), default="guided")
            command.add_argument("--budget", type=int, default=4)
            command.add_argument("--full-budget", type=int, default=4)
            command.add_argument("--samples", type=int, default=7)
            command.add_argument("--matrix", action="store_true")
            command.add_argument("--evidence", type=Path)
            command.add_argument("--markdown", type=Path)
            command.add_argument("--reference", type=Path, help="previous comparison JSON for calibration and novelty")
    args = parser.parse_args()
    if args.command != "scan" and args.vectors < 12:
        parser.error("--vectors must cover the 12 fixed boundary cases")
    if args.command == "compare":
        if min(args.budget, args.full_budget, args.samples) < 1 or args.full_budget > args.budget:
            parser.error("positive replay and timing budgets are required, with full-budget <= budget")
        report, evidence = compare(args)
        dump(report, args.output)
        if args.evidence:
            dump(evidence, args.evidence)
        if args.markdown:
            args.markdown.write_text(markdown(report))
        return 0 if report["selected"] else 1
    try:
        compiler = R1MSMCompiler(args.source)
        plan = compiler.plan(args.candidate)
    except ValueError as error:
        parser.error(str(error))
    scan = compiler.scan(plan)
    if args.command == "scan":
        if args.format == "json" or (args.format is None and args.output and args.output.suffix == ".json"):
            dump(scan, args.output)
        elif args.output:
            args.output.write_text(scan_text(scan))
        else:
            print(scan_text(scan), end="")
        return 0
    (lock, pattern), report = local_build(compiler, plan, args.vectors)
    if args.command == "build":
        if len(args.owner_hash160) != 20:
            parser.error("--owner-hash160 must be 20 bytes")
        report.update(owner_offset=lock.owner_start, lock_hex=lock.lock(args.owner_hash160).hex(),
                      otda_program_hex=pattern.program.hex(), otda_field_sizes=pattern.field_sizes)
    dump({"scan": scan, "result": report}, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

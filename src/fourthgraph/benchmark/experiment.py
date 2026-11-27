"""Compile, execute, compare and replay bounded Forth formula experiments."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from hashlib import sha256
from itertools import chain, combinations
import json
from pathlib import Path
import platform
import sys
from time import monotonic, perf_counter_ns

from fourthgraph import PROJECT_VERSION
from fourthgraph.bsv.artifacts import describe_script
from fourthgraph.compiler.formula_experiment import MAX_DEPTH, RULES, enumerate_orders, validate_rules
from fourthgraph.compiler.script_builder import ScriptBuilder
from fourthgraph.compiler.script_formula import FORMULA_PASSES, validate_formula_passes
from .formula_fixture import FIXTURES

SCHEMA = "4thgraph.formula-experiment/1"
LIMIT = 32
WORKERS = 4
TARGET = "bsv-genesis/canonical-bounded-scriptnum"
ROOT = Path(__file__).resolve().parents[1]


def digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(data).hexdigest()


def pass_sets():
    return [list(plan) for n in range(len(FORMULA_PASSES)+1) for plan in combinations(FORMULA_PASSES, n)
            if "search" not in plan or "stack" in plan]


def capabilities():
    return {"schema": SCHEMA, "compiler": PROJECT_VERSION, "target": TARGET,
            "fixtures": {name: list(fix.implementations) for name, fix in FIXTURES.items()},
            "plan_sets": pass_sets(), "requires": {"search": ["stack"]},
            "ordered_rules": RULES, "max_rule_depth": MAX_DEPTH, "max_candidates": LIMIT, "max_workers": WORKERS,
            "stages": ["formula", "graph", "terminal schedule and emission"], "commands": ["run", "next", "replay"]}


def freeze(fixture):
    # Include actual implementation files and resolved Forth imports, even for a dirty checkout.
    components = sorted(ROOT.rglob("*.py"))
    sources = {key: fixture.source(key) for key in fixture.implementations}
    builder = ScriptBuilder(sources[fixture.name].decode(), formula_passes=())
    frozen = {"schema": SCHEMA, "compiler_version": PROJECT_VERSION, "python": platform.python_version(),
              "fixture": fixture.name, "entry": fixture.entry, "target": TARGET, "engine": "fourthgraph.bsv.evaluate",
              "sources": {k: sha256(v).hexdigest() for k, v in sources.items()},
              "dependencies": [asdict(lib) for lib in builder.library_imports],
              "tool_sha256": digest({str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in components}),
              "vectors_sha256": digest(list(fixture.vectors())), "vector_count": sum(1 for _ in fixture.vectors())}
    return frozen, sources


def plan_spec(raw, fixture):
    if not isinstance(raw, dict) or set(raw) - {"passes", "rules", "implementation", "parent_id"}:
        raise ValueError("candidate must contain only passes, rules, implementation or parent_id")
    passes = raw.get("passes", [])
    if not isinstance(passes, list) or any(not isinstance(p, str) for p in passes):
        raise ValueError("passes must be an array of names")
    implementation = raw.get("implementation", fixture.name)
    if implementation not in fixture.implementations:
        raise ValueError("unknown registered implementation")
    return {"implementation": implementation, "rules": list(validate_rules(raw.get("rules", []))),
            "passes": list(validate_formula_passes(passes))}


def compile_row(raw, fixture, sources, frozen, trace):
    row = {"requested": raw, "compile": {"status": "failed"}, "test": {"status": "not_run"}}
    started = perf_counter_ns()
    try:
        spec = plan_spec(raw, fixture)
        row.update(id=digest([digest(frozen), spec, raw.get("parent_id")]), applied=spec)
        builder = ScriptBuilder(sources[spec["implementation"]].decode(), formula_passes=spec["passes"],
                                experimental_rules=spec["rules"], trace_formulas=trace)
        if [asdict(lib) for lib in builder.library_imports] != frozen["dependencies"]:
            raise ValueError("dependencies differ from the frozen contract")
        code, lowering = builder.emit(fixture.entry, b""), builder.formulas[fixture.entry]
        elapsed = perf_counter_ns() - started
        row.update(compile={"status": "passed", "lowering": lowering},
                   artifact=describe_script(code, listing=trace), source_sha256=frozen["sources"][spec["implementation"]])
        if trace:
            row["trace"] = {"formula_snapshots": builder.formula_snapshots[fixture.entry], "target_stack_plan": "not_instrumented"}
    except (ValueError, TypeError, KeyError) as exc:
        elapsed = perf_counter_ns() - started
        row["compile"]["diagnostic"] = str(exc)
    row["compile"]["elapsed_ns"] = elapsed
    return row


def stable(row):
    fields = ("requested", "id", "source_sha256", "applied", "artifact", "test", "next", "trace")
    return {**{key: row.get(key) for key in fields},
            "delta": {key: value for key, value in row.get("delta", {}).items() if not key.endswith("_ns_observed")},
            "compile": {key: value for key, value in row["compile"].items() if key != "elapsed_ns"}}


def report_id(report):
    request = report["request"]
    return digest([report["snapshot"], request["axis"], request.get("parent_run"),
                   report["baseline"], report["baseline_bytes"], [stable(row) for row in report["candidates"]]])


def matching_baseline(axis, fixture, eligible, parents, previous):
    if not eligible:
        return None
    plan = dict(eligible[0]["applied"])
    if axis == "A":
        plan.update(passes=[], rules=[])
    else:
        plan["implementation"] = fixture.name
    for row in chain(eligible, parents.values()):
        if row["applied"] == plan:
            return {"id": row["id"], "applied": plan, "bytes": row["artifact"]["bytes"]}
    inherited = previous["baseline"] if previous else None
    return inherited if inherited is not None and inherited["applied"] == plan else None


def counted(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low},{high}]")
    return value


def run(request, previous=None, *, replaying=False):
    if not isinstance(request, dict) or set(request) - {"fixture","plans","workers","trace","snapshot","parent_run",
                                                        "axis","max_candidates","time_ms","enumerate","depth","terminal"}:
        raise ValueError("unknown experiment request fields")
    fixture = FIXTURES[request["fixture"]]
    frozen, sources = freeze(fixture)
    identity = digest(frozen)
    if request.get("snapshot", identity) != identity:
        raise ValueError("frozen snapshot mismatch")
    if bool(previous) != bool(request.get("parent_run")):
        raise ValueError("follow-up requires its parent report")
    if previous and (previous["snapshot"] != identity or previous["run_id"] != request["parent_run"]
                     or previous["run_id"] != report_id(previous)):
        raise ValueError("parent run or snapshot mismatch")
    axis = request.get("axis", "A")
    if axis not in ("A","B"):
        raise ValueError("choose axis A or B")
    plans = request.get("plans")
    mode = request.get("enumerate")
    if mode is not None:
        if plans is not None or axis != "A":
            raise ValueError("enumeration requires axis A without explicit plans")
        if mode == "sets":
            plans = [{"passes": p} for p in pass_sets()]
        elif mode == "orders":
            ir = ScriptBuilder(sources[fixture.name].decode(), formula_passes=()).formula_ir[fixture.entry]
            plans = [{"rules": list(r), "passes": request.get("terminal", ["stack"])}
                     for r in enumerate_orders(ir, request.get("depth", MAX_DEPTH))]
        else:
            raise ValueError("unknown enumeration mode")
    minimum = 0 if replaying else 1
    if not isinstance(plans, list) or not minimum <= len(plans) <= LIMIT:
        raise ValueError(f"submit between {minimum} and {LIMIT} plans")
    if not all(isinstance(p, dict) for p in plans):
        raise ValueError("each plan must be an object")
    if axis == "A" and len({p.get("implementation", fixture.name) for p in plans}) > 1:
        raise ValueError("axis A freezes the source")
    workers = counted(request.get("workers", 1), 1, WORKERS, "workers")
    limit = counted(request.get("max_candidates", LIMIT), 1, LIMIT, "max_candidates")
    timeout = counted(request.get("time_ms", 60_000), 1, 300_000, "time_ms")
    trace = request.get("trace", False)
    if type(trace) is not bool:
        raise ValueError("trace must be boolean")
    parents = {r["id"]: r for r in previous["candidates"] if r["test"]["status"] == "passed"} if previous else {}
    for p in plans:
        if previous or "parent_id" in p:
            parent = parents.get(p.get("parent_id"))
            if not parent:
                raise ValueError("parent candidate missing or unverified")
            spec = plan_spec(p, fixture)
            prior = parent["applied"]
            if (axis == "A" and prior["implementation"] != spec["implementation"] or
                axis == "B" and (prior["passes"], prior["rules"]) != (spec["passes"], spec["rules"])):
                raise ValueError("parent comparison changes both axes")
    unique, seen, compiler_plans = [], set(), set()
    for raw in plans:
        try:
            spec = plan_spec(raw, fixture)
            key = digest([spec, raw.get("parent_id")])
            compiler_plans.add((tuple(spec["passes"]), tuple(spec["rules"])))
        except (TypeError, ValueError):
            key = digest(raw)
        if key not in seen:
            unique.append(raw)
            seen.add(key)
    if axis == "B" and len(compiler_plans) > 1:
        raise ValueError("axis B freezes the compiler plan")
    duplicates = len(plans) - len(unique)
    plans = unique
    rows, cache = [], {}
    deadline = None if replaying else monotonic() + timeout / 1000
    stop = "exhausted" if limit >= len(plans) else "candidate_budget"
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, min(limit,len(plans)), workers):
            if deadline is not None and monotonic() >= deadline:
                break
            group = plans[start:min(start+workers,limit)]
            batch = list(pool.map(lambda p: compile_row(p, fixture, sources, frozen, trace), group))
            for row in batch:
                if row["compile"]["status"] == "passed":
                    artifact = row["artifact"]
                    key = identity, artifact["sha256"]
                    if key not in cache:
                        cache[key] = fixture.check(bytes.fromhex(artifact["hex"]))
                    row["test"] = cache[key]
                rows.append(row)
    if deadline is not None and monotonic() >= deadline:
        stop = "time_budget"
    eligible = [r for r in rows if r["test"]["status"] == "passed"]
    baseline = matching_baseline(axis, fixture, eligible, parents, previous)
    base_size = baseline["bytes"] if baseline else None
    for row in eligible:
        size = row["artifact"]["bytes"]
        parent = parents.get(row["requested"].get("parent_id"))
        row["delta"] = {"baseline_bytes": size-base_size if base_size is not None else None,
                        "parent_bytes": size-parent["artifact"]["bytes"] if parent else None}
        spec = row["applied"]
        row["metrics"] = {"script_bytes": size, "compile_ns": row["compile"]["elapsed_ns"],
                          "main_peak_items": row["test"]["main_peak_items"], "alt_peak_items": row["test"]["alt_peak_items"],
                          "transaction_bytes": {"status":"not_measured"}, "caller_bytes":{"status":"not_measured"}}
        if parent:
            row["delta"]["parent_main_peak_items"] = row["test"]["main_peak_items"] - parent["test"]["main_peak_items"]
            row["delta"]["parent_alt_peak_items"] = row["test"]["alt_peak_items"] - parent["test"]["alt_peak_items"]
            row["delta"]["parent_compile_ns_observed"] = row["compile"]["elapsed_ns"] - parent["compile"]["elapsed_ns"]
        row["next"] = []
        if axis == "A" and "stack" in spec["passes"] and "search" not in spec["passes"]:
            row["next"].append({**spec, "passes": spec["passes"]+["search"], "parent_id":row["id"]})
    order = sorted(eligible, key=lambda r:(r["artifact"]["bytes"], len(r["applied"]["passes"])+len(r["applied"]["rules"]), r["id"]))
    def costs(row):
        return (row["artifact"]["bytes"], row["test"]["main_peak_items"], row["test"]["alt_peak_items"],
                row["compile"]["elapsed_ns"])
    frontier = []
    for row in eligible:
        current = costs(row)
        if not any(costs(other) != current and all(a <= b for a,b in zip(costs(other), current))
                   for other in eligible):
            frontier.append(row["id"])
    incumbents = list(parents.values()) + eligible
    def rank(r):
        return r["artifact"]["bytes"], len(r["applied"]["rules"])+len(r["applied"]["passes"]), r["id"]
    winner = min(incumbents, key=rank)["id"] if incumbents else None
    # Replays fix the exact admitted sequence, independent of the original wall-clock cutoff.
    replay = {"fixture": fixture.name, "plans": [r["requested"] for r in rows], "axis": axis, "trace": trace,
              "workers": 1, "time_ms": 300_000, "snapshot": identity}
    if previous:
        replay["parent_run"] = previous["run_id"]
    report = {"schema": SCHEMA, "snapshot": identity, "frozen": frozen, "request": replay, "candidates": rows,
              "baseline": baseline, "baseline_bytes": base_size, "ranking": [r["id"] for r in order],
              "ranking_scope": "fixture script bytes, then fewer passes", "winner_including_parents": winner,
              "observed_frontier": frontier, "frontier_costs": ["script_bytes", "main_peak_items", "alt_peak_items", "compile_ns"],
              "requested": request, "deduplicated_plans": duplicates, "stop": stop}
    return {**report, "run_id": report_id(report)}


def next_request(report):
    plans = [p for row in report["candidates"] if row["test"]["status"] == "passed"
             and row["delta"]["baseline_bytes"] is not None and row["delta"]["baseline_bytes"] < 0 for p in row["next"]]
    if not plans:
        return {"stop": "no_improving_expansion"}
    return {"fixture": report["frozen"]["fixture"], "plans": plans[:LIMIT],
            "snapshot": report["snapshot"], "parent_run": report["run_id"]}


def read(path):
    return json.loads(Path(path).read_text() if path != "-" else sys.stdin.read())


def main(argv=None):
    cli = argparse.ArgumentParser(prog="4thgraph experiment")
    sub = cli.add_subparsers(dest="cmd", required=True)
    sub.add_parser("capabilities")
    for name in ("run","next","replay"):
        parser = sub.add_parser(name)
        parser.add_argument("file", help="JSON file or - for stdin")
        if name != "next":
            parser.add_argument("--parent", help="previous batch's JSON report")
    args = cli.parse_args(argv)
    try:
        if args.cmd == "capabilities":
            result = capabilities()
        elif args.cmd == "next":
            result = next_request(read(args.file))
        else:
            data = read(args.file)
            replaying = args.cmd == "replay"
            result = run(data["request"] if replaying else data, read(args.parent) if args.parent else None,
                         replaying=replaying)
            if replaying and (data["run_id"] != result["run_id"] or data["run_id"] != report_id(data)):
                raise ValueError("replay differs from the recorded baseline, artifacts, verdicts, or formula traces")
        print(json.dumps(result, sort_keys=True))
    except (KeyError, ValueError, TypeError, OSError) as exc:
        print(json.dumps({"schema": SCHEMA, "status":"failed", "diagnostic":str(exc)}))
        raise SystemExit(2) from exc

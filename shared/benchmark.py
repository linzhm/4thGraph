"""Run Script Lab transaction benchmarks and the existing acceptance suites."""
import argparse
from importlib import import_module
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory

from .benchmark_cases import MODES, batch_shapes, workloads
from .benchmark_validation import (
    ACTIVATION_HEIGHT, CONTEXT_PIN, CORE_PIN, NODE_FLAGS, SPEND_HEIGHT, UTXO_HEIGHT,
    Node, acceptance, chain_metadata, measure_leg,
)

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = {
    "p2pk-p2pkh-baseline": (CONTEXT_PIN, ("test_acceptance",)),
    "p2pkh-r1": (CORE_PIN, ("test_payment", "test_payment_acceptance", "test_fixed_templates",
                            "test_curve_compiler", "test_lock_security")),
    "p2pkh-r1-deferred": (CORE_PIN, ("test_activation_acceptance", "test_node")),
    "p2pkh-sm2": (CORE_PIN, ("test_sm2", "test_sighash", "test_node", "test_otda_constructor", "test_signed_data",
                            "test_signed_data_acceptance")),
    "p2pkh-schnorr": (CONTEXT_PIN, ("test_schnorr", "test_musig2")),
    "lamport-ots": (CORE_PIN, ("test_acceptance", "test_node", "test_lamport")),
    "wots-plus": (CONTEXT_PIN, ("test_acceptance", "test_node", "test_wots")),
    "ml-dsa": (CONTEXT_PIN, ("test_payment", "test_mldsa", "test_shake_script",
                             "test_signature_script", "test_challenge_script", "check_chain_gang")),
}


def dump_json(path, document):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def summarize(template, name, scenarios):
    shapes = batch_shapes(template)
    results = {}
    for mode in MODES:
        stem = f"{name}/{mode:02x}/"
        expected = {f"{stem}batch/{i}x{o}" for i, o in shapes}
        expected.update((stem + "direct-exit", stem + "turnover"))
        actual = {key for key in scenarios if key.startswith(stem)}
        if actual != expected:
            raise ValueError(f"unexpected benchmark scenarios: missing={expected - actual}, extra={actual - expected}")
        batches = {}
        for inputs, outputs in shapes:
            shape = f"{inputs}x{outputs}"
            batches[shape] = scenarios[stem + "batch/" + shape]["payment"]["transaction_bytes"]
        base = batches["2x2"]
        extra_input = "3x3" if template.deferred else "3x2"
        lifecycle_cost = {}
        for scenario in ("direct-exit", "turnover"):
            phases = scenarios[stem + scenario]
            expected_phases = {"funding", "exit"}
            if template.deferred:
                expected_phases.add("activation")
            if scenario == "turnover":
                expected_phases.add("turnover")
            if phases.keys() != expected_phases:
                raise ValueError(f"incomplete {scenario} lifecycle: {list(phases)}")
            lifecycle_cost[scenario] = {phase: result["transaction_bytes"] for phase, result in phases.items()}
        results[f"{mode:02x}"] = {
            "batch_bytes": batches,
            "extra_input_bytes": None if template.deferred else batches[extra_input] - base,
            "extra_activation_pair_bytes": batches[extra_input] - base if template.deferred else None,
            "extra_output_bytes": batches["2x3"] - base,
            "lifecycle_bytes": lifecycle_cost,
            "lifecycle_total_bytes": {scenario: sum(phases.values())
                                      for scenario, phases in lifecycle_cost.items()},
        }
    return results


def collect(template, name, scratch, node, samples, profile_stack):
    scenarios = {}
    for case, phases in workloads(template, name, scratch):
        if case in scenarios:
            raise ValueError(f"duplicate cost scenario: {case}")
        baseline = case.endswith("/batch/2x2")
        scenarios[case] = {
            phase: measure_leg(leg, node, samples=samples if baseline else 0,
                               profile_stack=profile_stack and baseline, check_control=baseline)
            for phase, leg in phases.items()
        }
    return {"scenarios": scenarios, "costs": summarize(template, name, scenarios)}


def run_project(args):
    project, = args.project
    pin, test_names = PROJECTS[project]
    if args.alternate_pin:
        pin = CONTEXT_PIN if pin == CORE_PIN else CORE_PIN
    meta = chain_metadata()
    if meta["commit"] != pin:
        raise ValueError(f"{project}: expected chain-gang {pin}; found {meta}")
    ref = ROOT / "projects" / project / "reference"
    sys.path.insert(0, str(ref))
    cookie = os.environ.get("REGTEST_COOKIE")
    if cookie:
        cookie = str(Path(cookie).resolve())
    os.chdir(ref)
    node = None
    if args.chain_only:
        os.environ.pop("REGTEST_COOKIE", None)
    else:
        if not cookie:
            raise ValueError("set REGTEST_COOKIE or run through shared/verify_node.sh")
        os.environ["REGTEST_COOKIE"] = cookie
        node = Node(os.environ.get("REGTEST_URL", "http://127.0.0.1:18443"), cookie)
    adapter = import_module("benchmark_adapter")
    templates = adapter.TEMPLATES
    with TemporaryDirectory(prefix=f"{project}-benchmark-") as temp:
        workloads_by_template = {
            template_id: collect(template, f"{project}/{template_id}", Path(temp), node,
                                 args.samples, not args.no_stack)
            for template_id, template in templates.items()
        }
    test_results = None
    if not args.bench_only:
        test_results = acceptance(test_names, sys.stderr)
    measure_components = getattr(adapter, "components", None)
    component_results = measure_components(args.samples) if measure_components and not args.alternate_pin else None
    result = {
        "python_version": platform.python_version(), "components": component_results,
        "chain_gang": meta, "bsv_node_version": node.version if node else None,
        "templates": workloads_by_template, "acceptance": test_results,
        "passed": bool(test_results is not None and test_results["passed"] and node),
    }
    dump_json(args.output, result)
    return int(test_results is not None and not test_results["passed"])


def markdown(report, *, chinese):
    if chinese:
        lines = ["# BSV Script Lab 交易基准", "",
                 "单位为完整签名交易的字节数。节点验证使用显式提供的上一输出。", "",
                 "项目 | 模板 | 签名模式 | 两进两出 | 新增输入 | 新增激活对 | 新增输出 | 入金与退出 | 一次周转"]
    else:
        lines = ["# BSV Script Lab transaction benchmark", "",
                 "Sizes are serialized signed transaction bytes. Node verification uses supplied prevouts.", "",
                 "Project | Template | Sighash | 2×2 | Extra input | Extra activation pair | Extra output | Fund and exit | One turnover"]
    lines.extend(["---|---|---|---:|---:|---:|---:|---:|---:"])
    for project, result in report["projects"].items():
        for template, measure in result.get("templates", {}).items():
            for flag, row in measure["costs"].items():
                total = row["lifecycle_total_bytes"]
                cells = (project, template, f"0x{flag}", row["batch_bytes"]["2x2"], row["extra_input_bytes"],
                         row["extra_activation_pair_bytes"], row["extra_output_bytes"],
                         total["direct-exit"], total["turnover"])
                lines.append(" | ".join("—" if x is None else str(x) for x in cells))
    lines.extend(["", "## 验收" if chinese else "## Acceptance", ""])
    for project, result in report["projects"].items():
        status = ("通过" if chinese else "Passed") if result["passed"] else ("未完成" if chinese else "Incomplete")
        suite = result.get("acceptance") or {}
        lines.append(f"- {project} · {status} · {len(suite.get('tests', []))} "
                     + ("项测试" if chinese else "test methods"))
    return "\n".join(lines) + "\n"


def invoke(python, project, flags):
    if not python.is_file():
        return {"passed": False, "error": f"missing project interpreter: {python}"}
    with TemporaryDirectory(prefix="script-lab-benchmark-") as temp:
        output = Path(temp) / "project.json"
        command = [str(python), "-m", "shared.benchmark", "--worker", "--project", project,
                   "--output", str(output), *flags]
        completed = subprocess.run(command, cwd=ROOT)
        if not output.exists():
            return {"passed": False, "error": f"worker exited {completed.returncode} before producing results"}
        return json.loads(output.read_text())


def pin_comparison(primary, alternate):
    if "error" in primary or "error" in alternate:
        return {"compared": False, "error": primary.get("error") or alternate["error"]}

    def observations(result):
        cases = {}
        for template in result["templates"].values():
            for case, legs in template["scenarios"].items():
                for phase, row in legs.items():
                    cases[f"{case}/{phase}"] = (row["txid"], row["chain_gang"]["transaction"])
                    if control := row["changed_locktime_control"]:
                        cases[f"{case}/{phase}/changed-locktime"] = (control["txid"], control["chain_gang"])
        return cases

    first, second = observations(primary), observations(alternate)
    mismatch = sorted(key for key in first.keys() | second.keys() if first.get(key) != second.get(key))
    return {"compared": True, "matched": not mismatch, "case_count": len(first),
            "alternate": alternate["chain_gang"], "mismatches": mismatch}


def orchestrate(args):
    args.output.mkdir(parents=True, exist_ok=True)
    projects = {}
    for project in args.project or PROJECTS:
        print(f"Benchmarking {project}", file=sys.stderr, flush=True)
        flags = ["--samples", str(args.samples)]
        for enabled, option in ((args.chain_only, "--chain-only"), (args.bench_only, "--bench-only"),
                                (args.no_stack, "--no-stack")):
            if enabled:
                flags.append(option)
        result = invoke(args.venvs_dir / project / "bin/python", project, flags)
        if args.alternate_venvs_dir:
            print(f"Comparing the other chain-gang pin for {project}", file=sys.stderr, flush=True)
            alternate = invoke(args.alternate_venvs_dir / project / "bin/python", project,
                               ["--alternate-pin", "--chain-only", "--bench-only", "--no-stack", "--samples", "0"])
            result["pin_comparison"] = pin_comparison(result, alternate)
        projects[project] = result
    compared = not args.alternate_venvs_dir or all(
        result.get("pin_comparison", {}).get("matched", False) for result in projects.values()
    )
    report = {
        "schema_version": 1,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "dirty_worktree": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)),
        "platform": platform.platform(),
        "node_scope": "isolated regtest verifyscript against explicit prevouts",
        "cost_case_context": {"spend_height": SPEND_HEIGHT, "activation_height": ACTIVATION_HEIGHT,
                              "utxo_height": UTXO_HEIGHT, "node_flags": NODE_FLAGS},
        "timing": {"warmup": 1, "samples": args.samples, "unit": "ms",
                   "includes": "chain-gang Python adapter or BSV Node local HTTP round trip"},
        "projects": projects,
        "pin_comparison_passed": compared if args.alternate_venvs_dir else None,
        "passed": compared and all(result["passed"] for result in projects.values()),
    }
    dump_json(args.output / "benchmark.json", report)
    for lang in ("en", "zh-CN"):
        (args.output / f"benchmark.{lang}.md").write_text(
            markdown(report, chinese=lang == "zh-CN"), encoding="utf-8",
        )
    if args.bench_only:
        return int(not compared or any("error" in result for result in projects.values()))
    if args.chain_only:
        return int(not compared or any(not (result.get("acceptance") or {}).get("passed") for result in projects.values()))
    return int(not report["passed"] or not compared)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--venvs-dir", type=Path, help="contains <project>/bin/python for each enabled project")
    parser.add_argument("--alternate-venvs-dir", type=Path,
                        help="optional project interpreters with the other chain-gang pin")
    parser.add_argument("--alternate-pin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--project", action="append", choices=PROJECTS)
    parser.add_argument("--output", required=True, type=Path, help="report directory")
    parser.add_argument("--samples", type=int, default=5, help="timed repetitions for each 2×2 case")
    parser.add_argument("--chain-only", action="store_true", help="diagnostic run without node verdicts")
    parser.add_argument("--bench-only", action="store_true", help="diagnostic run without project acceptance suites")
    parser.add_argument("--no-stack", action="store_true", help="skip the development stack measurement")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.samples < 0 or len(set(args.project or ())) != len(args.project or ()):
        parser.error("sample count must be non-negative and project selection must be unique")
    args.output = args.output.resolve()
    if args.worker:
        try:
            return run_project(args)
        except (OSError, ValueError, RuntimeError) as error:
            dump_json(args.output, {"passed": False, "error": str(error)})
            print(error, file=sys.stderr)
            return 1
    if args.venvs_dir is None:
        parser.error("--venvs-dir is required")
    args.venvs_dir = args.venvs_dir.resolve()
    if args.alternate_venvs_dir:
        args.alternate_venvs_dir = args.alternate_venvs_dir.resolve()
    return orchestrate(args)


if __name__ == "__main__":
    raise SystemExit(main())

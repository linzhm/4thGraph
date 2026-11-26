"""Render the 4thGraph compiler decisions and their recorded replay evidence."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from protocol import CANDIDATE_ORDER, PROJECT_NAME, RANK_ORDER, artifact_digest, candidate_rank, select_candidate
from shared.transaction import Transaction

SCENARIOS = {
    "original": {"fused": "fused", "split": "split"},
    "constrained": {"fused": None, "split": "constrained"},
}
ROUTES = ("settle", "review")
LEGACY_PLANS = {"fused_settle": "fused", "fused_review": "fused",
                "split_settle": "split", "split_review": "constrained"}
CONTEXT_FIELDS = ("bsv_node_version", "chain_gang", "regtest_profile", "target", "topology", "optimization",
                  "join_witness", "chronicle_activation_height", "sample_count")


def read_replay(path):
    raw = path.read_bytes()
    return json.loads(raw), {"file": path.name, "sha256": sha256(raw).hexdigest()}


def context(replay):
    return {name: replay[name] for name in CONTEXT_FIELDS}


def output_matches(output, expected):
    return output.value == expected["satoshis"] and output.script == bytes.fromhex(expected["script_hex"])


def transaction_from_record(row):
    tx = Transaction.parse(bytes.fromhex(row["raw"]))
    previous = [f"{item.txid[::-1].hex()}:{item.vout}" for item in tx.inputs]
    if (row["txid"] != tx.txid() or row["bytes"] != len(tx.serialize()) or row["previous"] != previous
            or row["transaction_version"] != tx.version):
        raise ValueError("recorded transaction metadata does not match the raw transaction")
    if len(row["bsv_node"]["input_scripts"]) != len(tx.inputs):
        raise ValueError("recorded Node verdicts do not match the input count")
    return tx


def positive_passed(row):
    node = row["bsv_node"]
    return (bool(node["input_scripts"]) and all(flag is True for flag in node["input_scripts"])
            and node["mempool"] is True and node["mined"] is True and row["chain_gang"]["transaction"] is True)


def control_passed(name, row):
    node = row["bsv_node"]
    live_only = name == "missing_from_utxo_set"
    return (bool(node["input_scripts"]) and all(flag is live_only for flag in node["input_scripts"])
            and node["mempool"] is False and node["mined"] is False
            and node.get("rpc_code") == (-25 if live_only else -26) and row["chain_gang"]["transaction"] is False)


def measure_case(case, artifact, bootstrap):
    steps = case["steps"]
    templates = artifact["templates"]
    names = ["deploy", *(step["name"] for step in templates)]
    if set(names) != steps.keys():
        raise ValueError("steps do not match the candidate transaction graph")
    txs = {name: transaction_from_record(steps[name]) for name in names}
    versions = artifact["supported_transaction_versions"]
    if any(tx.version not in versions for tx in txs.values()):
        raise ValueError("replay contains a transaction version outside the artifact target")
    deploy = txs["deploy"]
    if (len(deploy.inputs) != 1 or deploy.inputs[0].txid != bootstrap.txid_wire()
            or deploy.inputs[0].vout >= len(bootstrap.outputs) or len(deploy.outputs) != 1
            or not output_matches(deploy.outputs[0], artifact["deploy_output"])):
        raise ValueError("deployment does not match the bootstrap and candidate output")
    for step in templates:
        expected = [(txs[ref["step"]], ref["vout"]) for ref in step["inputs"]]
        actual = [(item.txid, item.vout) for item in txs[step["name"]].inputs]
        if actual != [(parent.txid_wire(), vout) for parent, vout in expected] or any(
            vout >= len(parent.outputs) for parent, vout in expected
        ):
            raise ValueError(f"{step['name']} does not spend its bound parents")
    terminal = txs[names[-1]].outputs
    if len(terminal) != 1 or not output_matches(terminal[0], artifact["terminal_outputs"][case["route"]]):
        raise ValueError("terminal output does not match the reported route")
    metrics = case["metrics"]
    sizes = [steps[name]["bytes"] for name in names]
    if metrics["whole_path_bytes"] != sum(sizes) or metrics["max_transaction_bytes"] != max(sizes):
        raise ValueError("recorded transaction size metrics do not match the raw transactions")

    controls = {}
    for name, row in case["controls"].items():
        transaction_from_record(row)
        missing = row["chain_gang"]["missing_outpoints"]
        if name == "missing_from_utxo_set" and missing != [row["previous"][int(case["route"] == "settle")]]:
            raise ValueError("missing-result control records the wrong absent outpoint")
        controls[name] = {
            "passed": control_passed(name, row), "txid": row["txid"], "missing_outpoints": missing,
            "node_rpc_code": row["bsv_node"].get("rpc_code"),
        }
    passed = all(positive_passed(row) for row in steps.values()) and all(row["passed"] for row in controls.values())
    return {
        "status": "passed" if passed else "failed",
        "artifact_sha256": case["artifact_sha256"],
        "inputs": case["data"], "metrics": metrics,
        "step_txids": {name: steps[name]["txid"] for name in names},
        "transaction_versions": {name: tx.version for name, tx in txs.items()},
        "measured_minus_estimated_bytes": metrics["whole_path_bytes"] - artifact["estimated_cost"]["whole_path_bytes"],
        "controls": controls,
    }


def present_candidate(replay, scenario, name, candidate, source_digest, bootstrap, used_cases):
    routes = dict.fromkeys(ROUTES, {"status": "not_run"})
    if not candidate["eligible"]:
        return {**candidate, "static_status": "excluded", "replay": routes}
    plan_id = SCENARIOS[scenario][name]
    artifact = replay["plans"][plan_id]
    digest = artifact["artifact_sha256"]
    if (artifact_digest(artifact) != digest or candidate["artifact_sha256"] != digest
            or artifact["source_sha256"] != source_digest or artifact["schedule"] != name
            or artifact["compiler_version"] != replay["compiler_version"]
            or any(artifact[key] != replay[key] for key in ("target", "topology", "optimization", "join_witness"))):
        raise ValueError(f"{scenario}/{name} artifact digest, source, or build settings do not match")
    graph = [{key: row[key] for key in template} for row, template in
             zip(candidate["graph"], artifact["templates"], strict=True)]
    words = {step: {key: value for key, value in build.items() if key != "word"}
             for step, build in candidate["words"].items()}
    if (graph != artifact["templates"] or candidate["cost"] != artifact["estimated_cost"]
            or words != artifact["word_builds"] or tuple(candidate["rank"]) != candidate_rank(candidate["cost"])):
        raise ValueError(f"{scenario}/{name} decision does not match the compiled artifact")
    for route in ROUTES:
        case_id = f"{plan_id}_{route}"
        if case_id in replay["cases"]:
            used_cases.add(case_id)
            case = replay["cases"][case_id]
            if (case["source_sha256"], case["artifact_sha256"], case["scenario"], case["candidate"], case["route"]) != (
                source_digest, digest, scenario, name, route
            ):
                raise ValueError(f"{case_id} does not match its source, artifact, candidate, or route")
            try:
                routes[route] = measure_case(case, artifact, bootstrap)
            except (KeyError, ValueError, IndexError) as error:
                raise ValueError(f"{case_id}: {error}") from error
    return {**candidate, "static_status": "eligible", "replay": routes}


def historical_record(path):
    replay, provenance = read_replay(path)
    if (replay["project"], replay["schema_version"], replay["compiler_version"]) != (PROJECT_NAME, 1, "0.1.0"):
        raise ValueError(f"{path.name} is not a v0.1.0 replay")
    if replay["cases"].keys() != LEGACY_PLANS.keys():
        raise ValueError(f"{path.name} does not contain the four v0.1.0 replay cases")
    cases = {}
    for name, plan_id in LEGACY_PLANS.items():
        case = replay["cases"][name]
        route = name.rsplit("_", 1)[1]
        artifact = replay["plans"][plan_id]
        if case["route"] != route or case["steps"].keys() != {"deploy", *(t["name"] for t in artifact["templates"])}:
            raise ValueError(f"{path.name}/{name} does not match its historical plan")
        label = "constrained_source" if plan_id == "constrained" else "source"
        cases[name] = {
            "scenario": "constrained" if plan_id == "constrained" else "original",
            "candidate": artifact["schedule"], "route": route,
            "source_sha256": sha256(replay[label].encode()).hexdigest(),
            "status": "passed" if all(positive_passed(row) for row in case["steps"].values()) else "failed",
            "metrics": case["metrics"],
        }
    return {**provenance, "compiler_version": replay["compiler_version"], "context": context(replay), "cases": cases}


def decision_report(replay_path, baselines=()):
    replay, provenance = read_replay(replay_path)
    if replay["project"] != PROJECT_NAME or replay["schema_version"] != 2:
        raise ValueError("a 4thGraph replay with schema_version 2 is required")
    bootstrap = Transaction.parse(bytes.fromhex(replay["bootstrap_raw"]))
    used_cases = set()
    scenarios = {}
    for name, source in (("original", replay["source"]), ("constrained", replay["constrained_source"])):
        decision = replay["decisions"][name]
        if decision["candidates"].keys() != SCENARIOS[name].keys():
            raise ValueError(f"{name} does not contain the expected candidates")
        source_digest = sha256(source.encode()).hexdigest()
        candidates = {key: present_candidate(replay, name, key, candidate, source_digest, bootstrap, used_cases)
                      for key, candidate in decision["candidates"].items()}
        if (select_candidate(candidates, decision["requested"]) != (decision["selected"], decision["selection_basis"])
                or tuple(decision["rank_order"]) != RANK_ORDER or tuple(decision["tie_break_order"]) != CANDIDATE_ORDER):
            raise ValueError(f"{name} selection does not match the static ranking")
        scenarios[name] = {**decision, "source_sha256": source_digest, "candidates": candidates}
    if used_cases != replay["cases"].keys():
        raise ValueError(f"unexpected replay cases: {sorted(replay['cases'].keys() - used_cases)}")
    history = sorted((historical_record(path) for path in baselines), key=lambda row: (row["file"], row["sha256"]))
    if len({row["sha256"] for row in history}) != len(history):
        raise ValueError("duplicate historical replay")
    return {
        "schema_version": 1, "project": PROJECT_NAME, "compiler_version": replay["compiler_version"],
        "replay": {**provenance, "context": context(replay)},
        "scenarios": scenarios, "historical_baseline": history,
    }


SCENARIO_LABELS = {"original": "原始源码", "constrained": "带独立提交约束的源码"}
CANDIDATE_LABELS = {"fused": "融合", "split": "拆分"}
ROUTE_LABELS = {"settle": "结算", "review": "复核"}
BASIS_LABELS = {"explicit_request": "显式指定", "only_eligible_candidate": "唯一符合条件的候选",
                "lowest_rank": "静态成本排序最优"}


def markdown(report):
    replay = report["replay"]
    run = replay["context"]
    rows = [
        f"# 4thGraph v{report['compiler_version']} 编译决策报告",
        "",
        f"复放使用目标 {mark(run['target'])}，拓扑 {mark(run['topology'])}，优化 {mark(run['optimization'])}，"
        f"汇合见证 {mark(run['join_witness'])}。",
        f"BSV Node RPC 版本为 {run['bsv_node_version']}，chain-gang 提交为 {mark(run['chain_gang']['commit'])}。"
        f"节点配置为 {run['regtest_profile']}，Chronicle 激活高度为 {run['chronicle_activation_height']}，"
        f"每笔正向交易采样 {run['sample_count']} 次。",
        f"复放证据为 {mark(replay['file'])}，SHA-256 为 {mark(replay['sha256'])}。[决策报告 JSON](decision-report.json)",
        "",
        "每个引擎的耗时取路径上最大的单笔中位数。Node 耗时含本地 RPC，chain-gang 耗时含解析。"
        "栈峰值来自开发求值器对通过两引擎的输入进行剖析。",
    ]

    for name, scenario in report["scenarios"].items():
        picked = CANDIDATE_LABELS[scenario["selected"]]
        available = scenario["availability"]
        basis = BASIS_LABELS[scenario["selection_basis"]]
        rows.extend([
            "", f"## {SCENARIO_LABELS[name]}", "",
            f"选择**{picked}**，依据为{basis}。排序依次比较整路字节、单笔最大签名检查次数和依赖深度。",
            "当前同时可用的数据为 " + listed(available["data"]) + "，授权角色为 " + listed(available["authorizers"]) + "。",
            f"源码 SHA-256 为 {mark(scenario['source_sha256'])}。", "",
            "| 候选 | 路由 | 静态 | 复放 | 估算 / 实测 / 偏差 B | 最大单笔 B | Node / chain-gang ms | 主栈 / Alt / 合计 B | 深度 / 中间 UTXO |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ])
        for candidate, info in scenario["candidates"].items():
            for route, result in info["replay"].items():
                cells = [CANDIDATE_LABELS[candidate], ROUTE_LABELS[route], info["static_status"], result["status"]]
                estimate = info["cost"]["whole_path_bytes"] if info["eligible"] else "—"
                metrics = result.get("metrics")
                if metrics is None:
                    cells.extend([f"{estimate} / — / —", "—", "—", "—", "—"])
                else:
                    stack = metrics["peak_stack"]
                    cells.extend([
                        f"{estimate} / {metrics['whole_path_bytes']} / {result['measured_minus_estimated_bytes']:+d}",
                        str(metrics["max_transaction_bytes"]),
                        f"{metrics['max_single_transaction_bsv_verify_rpc_median_ms']:.3f} / "
                        f"{metrics['max_single_transaction_chain_gang_median_ms']:.3f}",
                        f"{stack['main_payload_bytes']} / {stack['alt_payload_bytes']} / {stack['combined_payload_bytes']}",
                        f"{metrics['dependency_depth_including_deploy']} / {metrics['intermediate_utxos']}",
                    ])
                rows.append("| " + " | ".join(cells) + " |")
        for candidate, info in scenario["candidates"].items():
            rows.extend(["", f"### {CANDIDATE_LABELS[candidate]}", ""])
            for step in info["graph"]:
                inputs = [f"{ref['step']}:{ref['vout']}" for ref in step["inputs"]]
                external = listed(step.get("external_inputs", ()))
                rows.append(f"- {mark(step['name'])} 花费 {listed(inputs)}，执行 {listed(step['executes'])}。"
                            f"外部输入为{external}，签名角色为{listed(step['authorizers'])}。")
            for reason in info.get("exclusions", ()):
                rows.append(f"- {reason['message']}。")
            for reason in info["boundary_reasons"]:
                rows.append(f"- {reason}。")
            if info["eligible"]:
                cost = info["cost"]
                assumptions = cost["assumptions"]
                values = [f"{key}={value}" for key, value in assumptions["external_u32_values"].items()]
                rows.extend([
                    f"- 构建 SHA-256 为 {mark(info['artifact_sha256'])}。",
                    f"- 静态估算使用 {listed(values)}、{assumptions['ecdsa_der_bytes']} B DER、"
                    f"{assumptions['deployment_inputs']} 个部署输入。排序值为 {list(info['rank'])}。",
                ])
                for step, word in info["words"].items():
                    rules = [f"{rewrite['rule']} L{rewrite['line']}:{rewrite['column']}" for rewrite in word["rewrites"]]
                    rows.append(f"- {mark(step)} 使用 {mark(word['word'])}，Script 为 {word['script_bytes']} B。"
                                f"改写为{listed(rules)}。")
    if report["historical_baseline"]:
        rows.extend([
            "", "## v0.1.0 历史基线", "",
            "历史归档按其原有计划记录。末列为带独立提交约束的拆分复核，"
            "各列为当时记录的整条路径字节。归档摘要与原始指标见 JSON。", "",
            "| 归档 | 融合结算 | 融合复核 | 拆分结算 | 受约束拆分复核 |",
            "| --- | ---: | ---: | ---: | ---: |",
        ])
        for old in report["historical_baseline"]:
            sizes = [str(old["cases"][case]["metrics"]["whole_path_bytes"]) for case in LEGACY_PLANS]
            rows.append("| " + " | ".join([mark(old["file"]), *sizes]) + " |")
    return "\n".join(rows) + "\n"


def mark(value):
    return chr(96) + str(value) + chr(96)


def listed(values):
    return "、".join(map(mark, values)) or "无"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("replay", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, action="append", default=[], help="v0.1.0 replay, repeatable")
    args = parser.parse_args()
    try:
        report = decision_report(args.replay, args.baseline)
        plain = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        summary = markdown(report)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "decision-report.json").write_text(plain, encoding="utf-8")
        (args.output_dir / "decision-report.md").write_text(summary, encoding="utf-8")
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()

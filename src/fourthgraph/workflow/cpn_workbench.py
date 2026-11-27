"""Export a portable CPN candidate workbench with its original evidence."""

import json
from hashlib import sha256
from importlib.resources import files

from fourthgraph.compiler.source import SourceCompiler, Tokens
from fourthgraph.reporting import control_passed, positive_passed, transaction_from_record
from fourthgraph.stdlib import LIBRARIES, read_library
from fourthgraph.workflow.proof_planner import planned_build
from fourthgraph.workflow.workflow_contract import state_fields


def carried_state(output, kind, step, build):
    if kind == "receipt" and output.value == build["receipt"]["satoshis"]:
        prefix = bytes.fromhex(build["receipt"]["script_prefix_hex"])
        if not output.script.startswith(prefix):
            return {}
        packet = output.script[len(prefix):]
    elif kind == "state":
        state = build.get("state_outputs", {}).get(step, build.get("state_output"))
        if state is None or output.value != state["satoshis"]:
            return {}
        suffix = bytes.fromhex(state["script_suffix_hex"])
        if not suffix or not output.script.endswith(suffix):
            return {}
        packet = output.script[:-len(suffix)]
    else:
        return {}
    if len(packet) != len(state_fields(bytes(32), 0)):
        return {}
    root, value = packet[1:33], int.from_bytes(packet[34:], "little")
    if value >= 1 << 32 or state_fields(root, value) != packet:
        return {}
    return {"state_u32": value, "root_txid": root[::-1].hex()}


def source_words(source_file, report):
    raw = source_file.read_bytes()
    if sha256(raw).hexdigest() != report["source_sha256"]:
        raise ValueError("workbench source differs from the candidate report")
    compiler = SourceCompiler(raw.decode("utf8"), source_path=source_file)
    if compiler.source_imports != report["imports"]:
        raise ValueError("workbench imports differ from the candidate report")
    words = {}
    for stage in compiler.workflow().stages:
        definition = compiler.definitions.get(stage.word.name)
        if definition is None:
            continue
        module = definition.module
        if module is None:
            data = raw
        elif module in LIBRARIES:
            data = read_library(module)
        else:
            data = (source_file.parent / module).read_bytes()
        if module is not None and sha256(data).hexdigest() != report["imports"][module]:
            raise ValueError(f"{module}: source changed while exporting the workbench")
        location = definition.location if module else f"{source_file.name}, {definition.location}"
        lines = data.decode("utf8").splitlines(keepends=True)
        line = lines[definition.line - 1]
        colon = line.rfind(":", 0, definition.column - 1)
        excerpt = ""
        if colon >= 0:
            tokens = Tokens(line[colon:] + "".join(lines[definition.line:]))
            for token in tokens:
                if token.name == ";":
                    excerpt = tokens.source[:tokens.offset]
                    break
        words[stage.name] = {"location": location, "source": excerpt}
    return words


def export_workbench(report_file, receipt_files, *, output, title, selected=None, source=None):
    original = json.loads(report_file.read_bytes())
    report = original.get("schedule_explanation", original)
    if report.get("schema_version") != 1 or not report["candidates"]:
        raise ValueError("expected a staged CPN candidate report")
    preferred = selected if selected is not None else report["selected"]
    if preferred is not None and preferred not in report["candidates"]:
        raise ValueError(f"unknown candidate {preferred!r}")
    packages = {}
    if "transaction_graph" in original:
        identity, plan = planned_build(original)
        packages[identity] = {"plan": plan.encode().decode("ascii")}
    for file in receipt_files:
        receipt = json.loads(file.read_bytes())
        if receipt.get("schema_version") != 1:
            raise ValueError(f"{file.name}: expected a version 1 CPN receipt")
        identity, plan = planned_build(receipt["build"], original=original)
        if "receipt" in packages.get(identity, {}):
            raise ValueError(f"duplicate receipt for {identity}")
        rows = [receipt["deployment"], *receipt["spends"]]
        if [row["step"] for row in receipt["spends"]] != [step["name"] for step in receipt["build"]["templates"]]:
            raise ValueError(f"{file.name}: replay steps differ from the build")
        kinds = {tx["step"]: [out["kind"] for out in tx["outputs"]]
                 for tx in receipt["build"]["transaction_graph"]["transactions"]}
        recorded = {}
        for row in rows:
            tx = transaction_from_record(row)
            if not positive_passed(row):
                raise ValueError(f"{file.name}: missing recorded validation and mining evidence")
            step = row.get("step", "deploy")
            recorded[step] = {
                "txid": tx.txid(), "bytes": len(tx.serialize()), "height": row["bsv_node"]["height"],
                "inputs": row["previous"],
                "outputs": [{"outpoint": f"{tx.txid()}:{slot}", "satoshis": item.value, "script_bytes": len(item.script),
                             **carried_state(item, kind, step, receipt["build"])}
                            for slot, (item, kind) in enumerate(zip(tx.outputs, kinds[step], strict=True))],
            }
        total = sum(row["bytes"] for row in rows)
        if receipt["measured_path_bytes"] != total:
            raise ValueError(f"{file.name}: incorrect measured path bytes")
        checks = [name for name, row in receipt["rejections"].items() if control_passed(name, row)]
        packages[identity] = {"plan": plan.encode().decode("ascii"), "receipt": receipt, "bytes": total,
                              "checks": checks, "transactions": recorded}

    public_fields = ("eligible", "measurement", "layout", "backend", "first_backend", "optimization", "cost",
                     "max_lock_bytes", "exclusions", "graph", "stage_roles", "assertions", "evidence_graph",
                     "stage_evidence", "sighash_family")
    order = dict.fromkeys([*report.get("ranked_candidates", ()), *report["candidates"]])
    candidates = [{"id": name, **{field: row[field] for field in public_fields if field in row}}
                  for name in order for row in (report["candidates"][name],)]
    payload = {"title": title, "current": report["request"]["current"], "sighash": report["request"]["sighash_family"],
               "selected": preferred, "candidates": candidates, "packages": packages, "report": original,
               "words": source_words(source, report) if source is not None else {}}
    write_workbench(payload, output)


def export_designer(*, output, title, model_file=None):
    """Open a fresh logical CPN draft without inventing a compiled report."""
    payload = {"title": title, "current": None, "sighash": "", "selected": None,
               "candidates": [], "packages": {}, "report": None, "words": {}, "editor_start": True}
    if model_file is not None:
        from fourthgraph.workflow.logical_cpn import parse_net

        payload["draft"] = parse_net(json.loads(model_file.read_bytes())).describe()
    write_workbench(payload, output)


def export_fixture(bundle_file, *, output, title):
    """Verify a fixed-parent test transaction before displaying its CPN."""
    from fourthgraph.replay.cctp_fixture import inspect_bundle

    bundle = json.loads(bundle_file.read_bytes())
    fixture = inspect_bundle(bundle)
    payload = {"title": title, "current": None, "sighash": "", "selected": None,
               "candidates": [], "packages": {}, "report": None, "words": {},
               "fixture_mode": True, "draft": bundle["cpn"], "fixture": fixture, "bundle": bundle}
    write_workbench(payload, output)


def write_workbench(payload, output):
    # Treat report content as data, including names and paths supplied by the caller.
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).replace("<", "\\u003c")
    assets = files("fourthgraph.workflow").joinpath("workbench")
    html = assets.joinpath("index.html").read_text(encoding="utf8")
    html = html.replace("/* STYLE */", assets.joinpath("graph.css").read_text(encoding="utf8"))
    html = html.replace("/* SCRIPT */", assets.joinpath("graph.js").read_text(encoding="utf8"))
    html = html.replace("<!-- DATA -->", data)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf8")

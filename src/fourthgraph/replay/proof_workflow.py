"""Fund and replay an explicitly selected CPN evidence plan on loopback regtest."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata
from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.replay.workflow import Replay, TestKeys
from fourthgraph.workflow.proof_planner import compile_evidence_plans, rebuild_candidate


def main(argv=None):
    cli = argparse.ArgumentParser(prog="4thgraph cpn replay", description=__doc__)
    cli.add_argument("source", type=Path)
    cli.add_argument("--candidate", required=True)
    cli.add_argument("--backend-catalog", type=Path)
    state = cli.add_mutually_exclusive_group(required=True)
    state.add_argument("--current", type=int)
    state.add_argument("--report", type=Path, help="rebuild and fund the exact candidate in this compiler report")
    cli.add_argument("--witness", metavar="NAME=UINT32", action="append", default=[])
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args(argv)
    try:
        witnesses = {}
        for item in args.witness:
            name, value = item.split("=", 1)
            if name in witnesses:
                raise ValueError(f"duplicate witness {name!r}")
            witnesses[name] = int(value)
        chain = chain_metadata()
        if chain["commit"] != CONTEXT_PIN:
            raise ValueError("the replay requires the pinned height-aware chain-gang")
        keys = TestKeys().public
        frontend = SourceCompiler(args.source.read_text(), source_path=args.source)
        with TemporaryDirectory(prefix="4thgraph-proof-workflow-") as scratch:
            if args.report:
                contract, artifact = rebuild_candidate(frontend, json.loads(args.report.read_text()),
                                                       args.candidate, scratch, args.backend_catalog)
                if any(keys.get(role) != key for role, key in contract.keys.items()):
                    raise ValueError("funded replay requires deterministic test keys for all roles")
            else:
                layout, _, _ = args.candidate.partition("/")
                contract, artifact = compile_evidence_plans(
                    frontend, keys, args.current, scratch, mode="auto" if layout == "path" else layout,
                    target="both", optimization="stack", objective="path-bytes", available_authorizers=None,
                    sighash_family="bip143", catalog=args.backend_catalog, selected=args.candidate)
            node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
            replay = Replay(node, 1, contract.target, int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"]),
                            script_timeout_us=2_000_000)
            bootstrap = replay.fund(1)
            parent, funding = replay.deploy(contract, bootstrap, 0)
            completed = {"deploy": parent}
            spends, rejections = [], {}
            for step in contract.plan.templates:
                started = perf_counter()
                draft = contract.prepare(step.name, completed, witnesses=witnesses)
                preparation_s = perf_counter() - started
                if len(draft.tx.outputs) == 2:
                    modified = replace(draft, tx=replace(draft.tx, outputs=draft.tx.outputs[::-1]))
                    rejections["reordered_outputs"] = {"step": step.name, **replay.record(
                        replay.sign(modified), modified.previous, expected=False)}
                tx = replay.sign(draft)
                spends.append({"step": step.name, **replay.record_step(draft, tx), "preparation_seconds": preparation_s})
                completed[step.name] = tx
            document = {
                "schema_version": 1, "build": artifact, "chain_gang": chain, "bsv_node_version": node.version,
                "profile": os.environ["SCRIPT_LAB_REGTEST_PROFILE"],
                "bootstrap": {"raw": bootstrap.serialize().hex(), "height": replay.traces[bootstrap.txid()]["height"]},
                "deployment": funding, "spends": spends, "rejections": rejections,
                "measured_path_bytes": sum(row["bytes"] for row in (funding, *spends)),
            }
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(document, indent=2) + "\n")
    except (ImportError, KeyError, OSError, ValueError) as error:
        cli.error(str(error))
    print(args.output)


if __name__ == "__main__":
    main()

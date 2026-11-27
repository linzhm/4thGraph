"""Plan, tune, replay and verify staged 4thGraph workflows."""

import argparse
import json
from pathlib import Path


def main(argv):
    cli = argparse.ArgumentParser(prog="4thgraph cpn", description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("plan", help="build and compare staged Script and proof candidates")
    commands.add_parser("tune", help="compare compiler lowering profiles across the same candidate plans")
    commands.add_parser("replay", help="fund, validate and mine a fixed candidate on loopback regtest")
    commands.add_parser("test-keys", help="print the deterministic regtest fixture public keys")
    check = commands.add_parser("check-model", help="validate and explore a logical CPN model")
    check.add_argument("model", type=Path)
    check.add_argument("--max-states", type=int, default=1000, help="maximum number of token markings to explore")
    check.add_argument("--max-tokens-per-place", type=int, default=16,
                       help="maximum token count per place in explored markings")
    inventory = commands.add_parser("inspect-evidence", help="inspect declared state, assertion and proof requirements")
    inventory.add_argument("model", type=Path)
    lower = commands.add_parser("lower-model", help="lower a supported logical CPN to a staged Forth workflow")
    lower.add_argument("model", type=Path)
    lower.add_argument("--source", type=Path, required=True, help="Forth definitions used by the graph")
    lower.add_argument("--output", type=Path, required=True, help="generated workflow in the source directory")
    archive = commands.add_parser("inspect-cctp", help="inspect an archived CCTP 2-to-2 transaction graph")
    archive.add_argument("archive", type=Path)
    archive.add_argument("--policy", type=Path, help="require a matching recipient-policy JSON")
    output = archive.add_mutually_exclusive_group()
    output.add_argument("--logical", action="store_true", help="emit a logical CPN model")
    output.add_argument("--flow-report", action="store_true", help="check bounded archived token flow")
    verify = commands.add_parser("verify", help="check a saved receipt and rerun Script validation offline")
    verify.add_argument("receipt", type=Path)
    verify.add_argument("--report", type=Path, help="compare against the original planning or tuning report")
    verify.add_argument("--candidate", help="require this exact candidate identity")
    workbench = commands.add_parser("workbench", help="export an interactive, offline CPN graph")
    workbench.add_argument("report", type=Path)
    workbench.add_argument("--receipt", type=Path, action="append", default=[])
    workbench.add_argument("--candidate", help="initial candidate to inspect")
    workbench.add_argument("--title", default="Staged workflow")
    workbench.add_argument("--source", type=Path, help="embed definitions from the matching Forth source")
    workbench.add_argument("--output", type=Path, required=True)
    design = commands.add_parser("design", help="create an offline editor for a new logical CPN")
    design.add_argument("--title", default="CPN draft")
    design.add_argument("--model", type=Path, help="start from a validated logical CPN model")
    design.add_argument("--output", type=Path, required=True)
    fixture = commands.add_parser("fixture-workbench", help="inspect a verified fixed-parent CCTP test transaction")
    fixture.add_argument("bundle", type=Path)
    fixture.add_argument("--title", default="CCTP historical-parent fixture")
    fixture.add_argument("--output", type=Path, required=True)
    declaration = commands.add_parser("fixture-declaration", help="describe the pinned 2-to-2 CCTP fixture as a CPN")
    declaration.add_argument("archive", type=Path)
    verify_fixture = commands.add_parser("verify-fixture", help="revalidate a fixed-parent CCTP fixture bundle")
    verify_fixture.add_argument("bundle", type=Path)
    if argv[:1] in (["plan"], ["tune"]):
        from fourthgraph.workflow.protocol import main as compiler_main

        return compiler_main(argv[1:], cpn_action=argv[0])
    if argv[:1] == ["replay"]:
        from fourthgraph.replay.proof_workflow import main as replay_main

        return replay_main(argv[1:])
    args = cli.parse_args(argv)
    try:
        if args.command == "test-keys":
            from fourthgraph.replay.workflow import TestKeys

            report = {role: key.hex() for role, key in TestKeys().public.items()}
        elif args.command == "check-model":
            from fourthgraph.workflow.logical_cpn import analyze, parse_net, validate_document

            document = json.loads(args.model.read_bytes())
            report = validate_document(document)
            if report["ok"]:
                graph = parse_net(document)
                report["analysis"] = analyze(
                    graph, max_states=args.max_states, max_tokens_per_place=args.max_tokens_per_place)
            else:
                print(json.dumps(report, indent=2, sort_keys=True))
                raise SystemExit(1)
        elif args.command == "lower-model":
            from fourthgraph.workflow.logical_cpn_lowering import lower_linear

            source = args.source.resolve()
            output = args.output.resolve()
            if output.parent != source.parent or output == source or output == args.model.resolve():
                raise ValueError("output must be a separate file in the Forth source directory")
            _, generated = lower_linear(json.loads(args.model.read_bytes()), source.read_text(), source_path=source)
            output.write_text(generated)
            print(output)
            return
        elif args.command == "inspect-evidence":
            from fourthgraph.workflow.logical_evidence import inventory

            report = inventory(json.loads(args.model.read_bytes()))
            if report["diagnostics"]:
                print(json.dumps(report, indent=2, sort_keys=True))
                raise SystemExit(1)
        elif args.command == "inspect-cctp":
            from fourthgraph.workflow.cctp_archive import flow_report, inspect_archive, logical_model, read_archive

            source, digest = read_archive(args.archive)
            policy = json.loads(args.policy.read_bytes()) if args.policy else None
            if args.flow_report:
                report = flow_report(source, archive_sha256=digest, policy=policy)
            else:
                graph = inspect_archive(source, archive_sha256=digest, policy=policy)
                report = logical_model(graph) if args.logical else graph
        elif args.command == "fixture-declaration":
            from fourthgraph.workflow.cctp_declared_fixture import fixture_declaration

            report = fixture_declaration(args.archive)
        elif args.command == "verify-fixture":
            from fourthgraph.replay.cctp_fixture import inspect_bundle

            report = inspect_bundle(json.loads(args.bundle.read_bytes()))
        elif args.command == "workbench":
            from fourthgraph.workflow.cpn_workbench import export_workbench

            export_workbench(args.report, args.receipt, output=args.output, title=args.title, selected=args.candidate,
                             source=args.source)
            print(args.output)
            return
        elif args.command == "design":
            from fourthgraph.workflow.cpn_workbench import export_designer

            export_designer(output=args.output, title=args.title, model_file=args.model)
            print(args.output)
            return
        elif args.command == "fixture-workbench":
            from fourthgraph.workflow.cpn_workbench import export_fixture

            export_fixture(args.bundle, output=args.output, title=args.title)
            print(args.output)
            return
        else:
            from fourthgraph.replay.cpn_receipt import verify_replay

            original = json.loads(args.report.read_bytes()) if args.report else None
            report = verify_replay(json.loads(args.receipt.read_bytes()), original=original, selected=args.candidate)
    except (ImportError, IndexError, KeyError, OSError, TypeError, ValueError) as error:
        cli.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))

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
    verify = commands.add_parser("verify", help="check a saved receipt and rerun Script validation offline")
    verify.add_argument("receipt", type=Path)
    verify.add_argument("--report", type=Path, help="compare against the original planning or tuning report")
    verify.add_argument("--candidate", help="require this exact candidate identity")
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
        else:
            from fourthgraph.replay.cpn_receipt import verify_replay

            original = json.loads(args.report.read_bytes()) if args.report else None
            report = verify_replay(json.loads(args.receipt.read_bytes()), original=original, selected=args.candidate)
    except (ImportError, KeyError, OSError, TypeError, ValueError) as error:
        cli.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))

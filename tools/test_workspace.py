"""Run the workspace's regression suites with their native test tools."""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys

from fourthgraph.benchmark.run import PROJECTS, ROOT


MATRIX_PROJECTS = (*PROJECTS, "pels-counter")
TARGETS = ("shared", *MATRIX_PROJECTS, "bsv-script-lean", "chain-gang")


def command_for(target, workspace):
    if target == "shared":
        modules = (
            "tests.test_benchmark", "tests.test_differential", "tests.test_evaluate",
            "tests.test_layout", "tests.test_one_time_signer", "tests.test_otda_reconstruction",
            "tests.test_verify_node",
        )
        return ROOT, [sys.executable, "-m", "unittest", *modules]
    if target in MATRIX_PROJECTS:
        return ROOT, [sys.executable, "-m", "tests.test_optimization_matrix", target]
    if target == "bsv-script-lean":
        return workspace / target, [
            "make", "numcheck", "flowcheck", "sighashcheck", "scripttests", "txtests",
        ]
    if target == "chain-gang":
        return workspace / target, ["cargo", "test", "--locked"]
    raise ValueError(f"Unknown test target: {target}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT.parent,
                        help="directory containing the sibling Lean and Rust checkouts")
    parser.add_argument("--project", action="append", choices=TARGETS,
                        help="run a specific target, repeat to select several (default: all)")
    args = parser.parse_args(argv)
    targets = tuple(dict.fromkeys(args.project or TARGETS))
    workspace = args.workspace.resolve()
    if any(target in MATRIX_PROJECTS for target in targets):
        engine = "chain-gang and BSV Node" if os.environ.get("REGTEST_COOKIE") else "chain-gang"
        print(f"Transaction matrix engines: {engine}", flush=True)

    results = {}
    for target in targets:
        cwd, command = command_for(target, workspace)
        print(f"\n=== {target} | {shlex.join(command)} ===", flush=True)
        try:
            results[target] = subprocess.run(command, cwd=cwd).returncode
        except OSError as error:
            print(f"Unable to start {target} in {cwd}: {error}", file=sys.stderr, flush=True)
            results[target] = None

    print("\n=== Test summary ===")
    for target, status in results.items():
        verdict = "ERROR (could not start)" if status is None else f"FAIL ({status})" if status else "PASS"
        print(f"{verdict:<24} {target}")
    return int(any(status != 0 for status in results.values()))


if __name__ == "__main__":
    sys.exit(main())

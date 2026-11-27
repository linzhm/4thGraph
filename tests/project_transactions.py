"""Replay a signed transaction example for each project in the source checkout."""

import argparse
from dataclasses import replace
from importlib import import_module
import os
from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory

from fourthgraph._paths import CHECKOUT
from fourthgraph.benchmark.cases import Leg, lifecycle, seed
from fourthgraph.benchmark.validation import Node, chain_verdict, measure_leg
from fourthgraph.bsv.transaction import Input, Transaction
from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.replay.workflow import TestKeys
from fourthgraph.verification.plan import compile_solutions
from fourthgraph.workflow.workflow_contract import WorkflowContracts


PAYMENT_TEMPLATES = {
    "p2pk-p2pkh-baseline": ("p2pk", "p2pkh"),
    "p2pkh-r1": ("scheduled-paired",),
    "p2pkh-r1-deferred": ("hash-only",),
    "p2pkh-schnorr": ("v0.7.0",),
    "p2pkh-sm2": ("v1.2.0",),
    "lamport-ots": ("committed-key-forth-compact",),
    "wots-plus": ("cached-steps-reconstructed",),
    "ml-dsa": ("pure-ml-dsa-44",),
}
PROJECTS = (*PAYMENT_TEMPLATES, "pels-counter", "workflow-examples", "proof-counter")
BIP143_ALL = 0x41


def payment_examples(project, scratch):
    # Adapters have project-local imports such as payment.py. Each runs in its own process.
    reference = CHECKOUT / "projects" / project / "reference"
    sys.path.insert(0, str(reference))
    adapter = import_module("benchmark_adapter")
    return {
        f"{name}/{phase}": leg
        for name in PAYMENT_TEMPLATES[project]
        for phase, leg in lifecycle(adapter.TEMPLATES[name], BIP143_ALL, True,
                                    f"transaction-example/{project}/{name}", scratch).items()
    }


def counter_examples(project):
    path = CHECKOUT / "projects" / project / "pels_counter.py"
    counter = run_path(str(path))
    source = counter["SOURCE"]
    advance = SourceCompiler(source.read_text(), source_path=source).words["advance"]
    _, candidates = counter["counter_builds"](advance)
    build = min(candidates, key=lambda candidate: candidate.describe()["path_bytes"])
    parent = Transaction((Input(seed(project), 0),), (build.root,))
    legs = {}
    controls = {}
    for state in (1, 2):
        current, successor, output = counter["next_counter"](parent, build.code, advance)
        if (current, successor) != (state - 1, state):
            raise ValueError("counter example did not advance by one")
        spend = build.spend(parent, output)
        legs[f"{current}-to-{successor}"] = Leg(spend, (parent,), (BIP143_ALL,))
        wrong = counter["counter_output"](build.code, successor + 1, output.value)
        controls[f"{current}-wrong-successor"] = Leg(
            build.spend(parent, wrong), (parent,), (BIP143_ALL,),
        )
        parent = spend
    return legs, controls


def workflow_examples(project):
    source = CHECKOUT / "projects" / project / "serial-graph.fth"
    workflow = SourceCompiler(source.read_text(), source_path=source).workflow()
    keys = TestKeys()
    contract = WorkflowContracts(workflow, keys.public, 19, mode="serial", target="both",
                                 sighash_family="both")
    parent = Transaction((Input(seed(project), 0),), contract.deployment_outputs)
    legs = {}
    for family in ("bip143", "otda"):
        completed = {"deploy": parent}
        for template in contract.plan.templates:
            draft = contract.prepare(template.name, completed, sighash_family=family)
            tx = draft.seal(keys.sign)
            completed[template.name] = tx
            legs[f"{family}/{template.name}"] = Leg(
                tx, tuple(item.parent for item in draft.previous), (draft.sighash,) * len(tx.inputs),
            )
    return legs


def proof_examples(project, scratch):
    source = CHECKOUT / "projects" / project / "verify-state.fth"
    frontend = SourceCompiler(source.read_text(), source_path=source)
    candidate, report = compile_solutions(frontend, TestKeys().public, 19, scratch)
    if report["selected"] != "script":
        raise ValueError("proof-counter example requires the direct Script backend")
    contract = candidate.contract
    parent = Transaction((Input(seed(project), 0),), (contract.root,))
    unsigned = contract.unsigned(parent, 20)
    wrong_terminal = replace(unsigned, outputs=(contract.terminals[0], unsigned.outputs[1]))
    if unsigned.outputs[0] == wrong_terminal.outputs[0]:
        raise ValueError("proof-counter negative example must change the terminal")
    return (
        {"direct-script": Leg(candidate.seal(unsigned), (parent,), (BIP143_ALL,))},
        {"wrong-terminal": Leg(candidate.seal(wrong_terminal), (parent,), (BIP143_ALL,))},
    )


def run_project(project, node):
    with TemporaryDirectory(prefix=f"{project}-transaction-test-") as temp:
        scratch = Path(temp)
        controls = {}
        if project in PAYMENT_TEMPLATES:
            legs = payment_examples(project, scratch)
        elif project == "pels-counter":
            legs, controls = counter_examples(project)
        elif project == "workflow-examples":
            legs = workflow_examples(project)
        else:
            legs, controls = proof_examples(project, scratch)
        for name, leg in legs.items():
            result = measure_leg(leg, node, check_control=True)
            print(f"{project}/{name} {result['txid']} {result['transaction_bytes']} B", flush=True)
        for name, leg in controls.items():
            chain = chain_verdict(leg.tx, leg.parents)
            node_results = node.verdicts(leg.tx, leg.parents) if node else ()
            if chain or any(node_results):
                raise ValueError(f"{project}/{name} accepted a transaction with incorrect outputs")
            print(f"{project}/{name} rejected", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", nargs="?", choices=PROJECTS)
    args = parser.parse_args()
    if args.project:
        cookie = os.environ.get("REGTEST_COOKIE")
        node = Node(os.environ.get("REGTEST_URL", "http://127.0.0.1:18443"), cookie) if cookie else None
        run_project(args.project, node)
        return
    failed = []
    for project in PROJECTS:
        command = [sys.executable, str(Path(__file__).resolve()), project]
        if subprocess.run(command, cwd=CHECKOUT).returncode:
            failed.append(project)
    if failed:
        parser.exit(1, f"Failed projects: {', '.join(failed)}\n")


if __name__ == "__main__":
    main()

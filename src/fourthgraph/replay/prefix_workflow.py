"""Replay a three-stage workflow through fixed offline parent transactions."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.script import asm
from fourthgraph.bsv.transaction import Input, Output, Transaction
from fourthgraph.compiler.source import FUSED_PREFIX, SourceCompiler
from fourthgraph.replay.workflow import TestKeys
from fourthgraph.workflow.workflow_contract import WorkflowContracts, compile_workflow


def replay(source, current=19):
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("prefix replay requires the pinned chain-gang build")
    raw = source.read_bytes()
    program = SourceCompiler(raw.decode(), source_path=source).workflow()
    keys = TestKeys()
    options = {"target": "bip143-v1"}
    _, explanation = compile_workflow(program, keys.public, current, source_bytes=raw, search=True, **options)
    reports = {}
    for layout in ("serial", FUSED_PREFIX):
        contract = WorkflowContracts(program, keys.public, current, mode=layout, **options)
        funding = Transaction((Input(bytes(32), 0),),
                              (Output(contract.root.value + 100, asm("OP_1")),), version=1)
        deploy = Transaction((Input(funding.txid_wire(), 0),), contract.deployment_outputs, version=1)
        done = {"deploy": deploy}
        records = []

        def validate(name, tx, parent, height, stages=()):
            validate_at_heights(tx, (parent,), spend_height=height, activation_height=100, utxo_heights=(height-1,))
            records.append({"step": name, "executes": stages, "txid": tx.txid(), "parent": parent.txid(),
                            "hex": tx.serialize().hex(), "bytes": len(tx.serialize()),
                            "parent_script_sha256": sha256(parent.outputs[0].script).hexdigest()})

        validate("deploy", deploy, funding, 4)
        for height, template in enumerate(contract.plan.templates, 5):
            draft = contract.prepare(template.name, done)
            tx = draft.seal(keys.sign)
            validate(template.name, tx, draft.parents[0], height, template.executes)
            done[template.name] = tx

        terminal = done[contract.plan.templates[-1].name].outputs
        artifact = contract.artifact(raw)
        reports[layout] = {"artifact_sha256": artifact["artifact_sha256"], "plan_sha256": artifact["plan_sha256"],
                           "funding_hex": funding.serialize().hex(), "transactions": records,
                           "whole_path_bytes": sum(row["bytes"] for row in records),
                           "max_transaction_bytes": max(row["bytes"] for row in records),
                           "terminal": terminal[0].serialize().hex(), "state": terminal[1].script[-5:].hex()}
        if layout == FUSED_PREFIX:
            first, last = contract.plan.templates
            draft = contract.prepare(first.name, {"deploy": deploy})
            output = draft.tx.outputs[0]
            state = (int.from_bytes(output.script[34:39], "little") + 1) % (1 << 32)
            bad_output = replace(output, script=output.script[:34] + state.to_bytes(5, "little") + output.script[39:])
            bad_draft = replace(draft, tx=replace(draft.tx, outputs=(bad_output,)))
            bad_state = bad_draft.seal(keys.sign)
            wrong_signer = draft.seal(lambda request: keys.sign(replace(request, authorizer=last.authorizers[0])))
            terminal_draft = contract.prepare(last.name, done)
            altered_parent = replace(done[first.name], locktime=1)
            bad_parent = replace(terminal_draft, payload=((altered_parent.serialize(),),)).seal(keys.sign)
            checks = {"wrong_state": (bad_state, deploy, 5), "wrong_authorization": (wrong_signer, deploy, 5),
                      "wrong_parent_opening": (bad_parent, done[first.name], 6)}
            rejected = []
            for name, (tx, parent, height) in checks.items():
                try:
                    validate_at_heights(tx, (parent,), spend_height=height, activation_height=100, utxo_heights=(height-1,))
                except (ValueError, RuntimeError):
                    rejected.append(name)
                else:
                    raise ValueError(f"chain-gang accepted {name}")
            other_deploy = replace(deploy, locktime=1)
            try:
                contract.prepare(last.name, {**done, "deploy": other_deploy})
            except ValueError:
                rejected.append("foreign_parent")
            else:
                raise ValueError("the compiler host accepted a foreign parent")
            reports[layout]["rejected"] = rejected
    if any(reports["serial"][key] != reports[FUSED_PREFIX][key] for key in ("terminal", "state")):
        raise ValueError("serial and fused-prefix changed the terminal result")
    return {"engine": engine, "source_sha256": sha256(raw).hexdigest(), "target": options["target"],
            "current": current, "search": explanation, "layouts": reports}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--current", type=int, default=19)
    args = parser.parse_args()
    print(json.dumps(replay(args.source, args.current), sort_keys=True))


if __name__ == "__main__":
    main()

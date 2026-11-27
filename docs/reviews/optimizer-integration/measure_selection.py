"""Measure the current Workflow implementations of a small PELS selection matrix."""

from hashlib import sha256
from itertools import product
import json
from pathlib import Path

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.transaction import Input, Transaction
from fourthgraph.compiler.source import SourceCompiler
from fourthgraph.replay.workflow import TestKeys, stack_peaks
from fourthgraph.workflow.workflow_contract import WorkflowContracts


LAYOUTS = (("bip143", "full"), ("bip143", "reconstructed"),
           ("otda", "reconstructed"), ("both", "reconstructed"))
CHAINS = ("fused", "serial")


def spend_path(contract, keys, root, families):
    steps = ("fused",) if contract.plan.mode == "fused" else ("prepare", "finish")
    completed = {"deploy": root}
    rows = []
    parent = root
    for offset, (step, family) in enumerate(zip(steps, families, strict=True)):
        draft = contract.prepare(step, completed, version=2, sighash_family=family)
        signed = draft.seal(keys.sign)
        validate_at_heights(signed, (parent,), spend_height=4 + offset, activation_height=2,
                            utxo_heights=(3 + offset,))
        rows.append({"stage": step, "family": family, "sighash": f"{draft.sighash:02x}",
                     "parent_txid": parent.txid(), "txid": signed.txid(),
                     "bytes": len(signed.serialize()),
                     "unlock_bytes": len(signed.inputs[0].script),
                     "stack_payload_peaks": stack_peaks(signed, draft.previous),
                     "chain_gang": True})
        completed[step] = parent = signed
    terminal, receipt = parent.outputs
    expected_receipt = b"\x00\x6a\x20" + root.txid_wire() + b"\x05\x09\x00\x00\x00\x00"
    if terminal != contract.terminals[1] or receipt.value != 0 or receipt.script != expected_receipt:
        raise ValueError("expected the ready label and the settlement payment")
    return {"families": families, "steps": rows,
            "path_bytes": len(root.serialize()) + sum(row["bytes"] for row in rows)}


def main():
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("review fixture requires pinned chain-gang")
    fixture = Path(__file__).with_name("selection-workflow.fth")
    source = fixture.read_bytes()
    workflow = SourceCompiler(source.decode(), source_path=fixture).workflow()
    keys = TestKeys()
    candidates = []
    for schedule, (family, layout) in product(CHAINS, LAYOUTS):
        options = {"mode": schedule, "target": "chronicle-v2", "optimization": "baseline",
                   "sighash_family": family}
        contract = WorkflowContracts(workflow, keys.public, 3, context_layout=layout, **options)
        chosen = WorkflowContracts(workflow, keys.public, 3, **options)
        root = Transaction((Input(bytes(32), 0),), (contract.root,))
        families = ("bip143", "otda") if family == "both" else (family,)
        routes = product(families, repeat=1 if schedule == "fused" else 2)
        candidates.append({
            "schedule": schedule, "family_policy": family, "layout": layout,
            "workflow_auto_layout": chosen.context_layout,
            "artifact_sha256": contract.artifact(source)["artifact_sha256"],
            "root_script_sha256": sha256(contract.root.script).hexdigest(),
            "root_script_bytes": len(contract.root.script), "root_tx_bytes": len(root.serialize()),
            "paths": [spend_path(contract, keys, root, selected) for selected in routes],
        })
    print(json.dumps({"chain_gang": engine, "source_sha256": sha256(source).hexdigest(),
                      "target": "chronicle-v2", "optimization": "baseline",
                      "stack_source": "development evaluator; native CHECKSIG modeled as true",
                      "scope": "Offline Workflow fixture with public test keys and actual parents, "
                               "including synthetic funding. Each path is tested independently.",
                      "candidates": candidates}, indent=2))


if __name__ == "__main__":
    main()

"""Validate the selected plan and rerun the saved Script checks with chain-gang."""

from fourthgraph.benchmark.validation import CONTEXT_PIN, chain_metadata
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.transaction import Transaction
from fourthgraph.reporting import control_passed, positive_passed, transaction_from_record
from fourthgraph.workflow.cpn import apply, check_effect
from fourthgraph.workflow.proof_planner import planned_build


def verify_replay(receipt, *, original=None, selected=None):
    if receipt.get("schema_version") != 1:
        raise ValueError("expected a version 1 funded CPN replay receipt")
    chain = chain_metadata()
    if chain["commit"] != CONTEXT_PIN or receipt["chain_gang"]["commit"] != CONTEXT_PIN:
        raise ValueError("receipt verification requires the pinned height-aware chain-gang")
    build = receipt["build"]
    identity, plan = planned_build(build, original=original, selected=selected)

    names = [template["name"] for template in build["templates"]]
    if [row["step"] for row in receipt["spends"]] != names or not names:
        raise ValueError("the receipt does not execute the selected workflow in order")
    bootstrap = Transaction.parse(bytes.fromhex(receipt["bootstrap"]["raw"]))
    parents = {bootstrap.txid_wire(): (bootstrap, receipt["bootstrap"]["height"])}
    activation = receipt["deployment"]["validation_context"]["activation_height"]
    marking, checked, seen = {}, {}, {}

    def run(row, tx, expected):
        ctx = row["validation_context"]
        actual = [parents[txin.txid] for txin in tx.inputs]
        heights = [height for _, height in actual]
        if (ctx["activation_height"] != activation or list(ctx["utxo_heights"]) != heights
                or any(height >= ctx["spend_height"] for height in heights)):
            raise ValueError("inconsistent previous transaction heights")
        try:
            validate_at_heights(tx, [parent for parent, _ in actual], **ctx)
        except (RuntimeError, ValueError) as error:
            if expected:
                raise ValueError(f"chain-gang rejected {tx.txid()}: {error}") from error
        else:
            if not expected:
                raise ValueError(f"chain-gang accepted control {tx.txid()}")
        return True

    rows = (receipt["deployment"], *receipt["spends"])
    for name, row in zip(("deploy", *names), rows, strict=True):
        tx = transaction_from_record(row)
        height = row["bsv_node"]["height"]
        if not positive_passed(row) or height != row["validation_context"]["spend_height"]:
            raise ValueError(f"missing recorded admission and mining evidence for {name}")
        effect = check_effect(plan, plan.index(name), tx, marking,
                              validate=lambda tx, _: run(row, tx, True), next_height=height)
        marking = apply(marking, effect)
        parents[tx.txid_wire()] = tx, height
        checked[name] = {"txid": tx.txid(), "bytes": row["bytes"], "chain_gang": True}
        seen[name] = tx

    controls = receipt["rejections"]
    if set(controls) != {"reordered_outputs"}:
        raise ValueError("missing reordered-output control")
    row = controls["reordered_outputs"]
    control, original = transaction_from_record(row), seen[names[-1]]
    if (row["step"] != names[-1] or len(original.outputs) != 2 or control.outputs != original.outputs[::-1]
            or tuple(v.outpoint() for v in control.inputs) != tuple(v.outpoint() for v in original.inputs)
            or not control_passed("reordered_outputs", row)):
        raise ValueError("invalid reordered-output control")
    run(row, control, False)

    total = sum(row["bytes"] for row in rows)
    if receipt["measured_path_bytes"] != total:
        raise ValueError("measured transaction byte total does not match the receipt")
    return {"candidate": identity, "artifact_sha256": build["artifact_sha256"], "plan_sha256": plan.digest,
            "measured_path_bytes": total, "chain_gang": chain, "transactions": checked,
            "controls": {"reordered_outputs": "rejected"}, "bsv_node": "recorded regtest verdicts"}

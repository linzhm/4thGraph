"""Replay fused, serial and two-input workflows and their recovery branches."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path

from compiler import PROJECT_NAME, PROJECT_VERSION, WORKFLOW_MODES, ParentOutput, SourceCompiler, evaluate
from lowering import OPTIMIZATIONS
from protocol import BINDING_CODE, DEFAULT_TARGET, FLAG, SIGHASH_FAMILY_OPTIONS, TARGETS, UTXO, invalidated
from recovery_replay import early_refund, refund_controls, snapshot, valid_with_live_inputs
from replay import SOURCE as FUNDING_COIN, Replay
from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.script import asm, encode_num, push
from shared.transaction import Input
from wordsets import U32
from workflow_contract import WorkflowContracts, compile_workflow

SOURCE = Path(__file__).with_name("proof") / "workflow.fth"
CASES = (("ordinary", 7), ("below-threshold", 18), ("at-threshold", 19), ("wrap", U32 - 1))


def metrics(rows, artifact):
    return {
        "whole_path_bytes": sum(row["bytes"] for row in rows),
        "max_transaction_bytes": max(row["bytes"] for row in rows),
        "max_node_rpc_median_ms": max(row["bsv_node"]["verify_rpc_median_ms"] for row in rows),
        "max_chain_gang_median_ms": max(row["chain_gang"]["median_ms"] for row in rows),
        "max_stack_payload_bytes": {key: max(row["stack"][key] for row in rows) for key in rows[0]["stack"]},
        "deployment_utxos": len(artifact["deployment_outputs"]),
        "intermediate_utxos": int(artifact["schedule"] == "serial"),
        "dependency_depth_including_deploy": len(rows),
    }


def with_first_output(draft, output):
    return replace(draft, tx=replace(draft.tx, outputs=(output, *draft.tx.outputs[1:])))


def first_controls(replay, contracts, draft, root, value):
    output, = draft.tx.outputs
    changed_state = contracts.state_output(root.txid_wire(), (value + 1) % U32)
    candidates = {
        "wrong_intermediate_value": changed_state,
        "wrong_intermediate_amount": replace(output, value=output.value - 1),
        "wrong_intermediate_script": replace(output, script=output.script + asm("OP_NOP")),
    }
    return {name: replay.record(replay.sign(with_first_output(draft, candidate)), draft.previous, expected=False)
            for name, candidate in candidates.items()}


def second_controls(replay, contracts, draft, done, first_draft, foreign_done, value, route):
    first, second = contracts.plan.program.stages
    root, parent = done["deploy"], done[first.name]
    foreign = contracts.prepare(second.name, foreign_done, version=draft.tx.version)
    other_state = foreign_done[first.name]
    try:
        contracts.prepare(second.name, {"deploy": root, first.name: other_state})
    except ValueError as error:
        wrong_root = str(error)
    else:
        raise ValueError("host accepted an intermediate output from a different workflow")

    # The alternate parent consumes the same root and creates identical outputs.
    # Re-sign after changing its bytes to obtain a distinct, valid alternative.
    alternate_first = replace(first_draft, tx=replace(first_draft.tx, locktime=1))
    alternate_parent = replay.sign(alternate_first)
    rebound = contracts.prepare(second.name, {"deploy": root, first.name: alternate_parent}, version=draft.tx.version)
    old_request, = draft.signing_requests()
    new_request, = rebound.signing_requests()
    if old_request.digest == new_request.digest or rebound.tx.inputs[0].txid != alternate_parent.txid_wire():
        raise ValueError("a changed parent did not change the child input and signing digest")

    terminal, _ = draft.tx.outputs
    controls = {
        "same_value_different_root": replace(foreign, tx=replace(foreign.tx, outputs=draft.tx.outputs)),
        "wrong_parent_opening": replace(draft, payload=((other_state.serialize(),),)),
        "same_root_different_parent_opening": replace(draft, payload=((alternate_parent.serialize(),),)),
        "wrong_terminal_script": with_first_output(draft, contracts.terminals[1 - route]),
        "wrong_terminal_amount": with_first_output(draft, replace(terminal, value=terminal.value - 1)),
        "wrong_receipt": replace(draft, tx=replace(draft.tx, outputs=(
            terminal, contracts.receipt(root.txid_wire(), (value + 1) % U32),
        ))),
    }
    rejected = {name: replay.record(replay.sign(candidate), candidate.previous, expected=False)
                for name, candidate in controls.items()}
    stale = draft.seal(lambda _: replay.keys.sign(new_request))
    rejected["stale_parent_authorization"] = replay.record(stale, draft.previous, expected=False)
    rebind = {
        "parent_before": parent.txid(), "parent_after": alternate_parent.txid(),
        "alternate_parent_raw": alternate_parent.serialize().hex(),
        "affected": invalidated(contracts.plan, first.name, parent, alternate_parent),
        "child_before": old_request.outpoint.text(), "child_after": new_request.outpoint.text(),
        "signing_digest_before": old_request.digest.hex(), "signing_digest_after": new_request.digest.hex(),
        "wrong_root_host_rejection": wrong_root,
    }
    return rejected, rebind


def atomic_inputs(draft, previous, roles, payload):
    inputs = tuple(Input(item.outpoint.txid, item.vout) for item in previous)
    template = replace(draft.template, authorizers=tuple(role for owners in roles for role in owners))
    return replace(draft, template=template, tx=replace(draft.tx, inputs=inputs),
                   previous=previous, input_authorizers=roles, payload=payload)


def atomic_controls(replay, contracts, draft, root, foreign, value, route):
    a, b = draft.previous
    a_role, b_role = draft.input_authorizers
    a_fields, b_fields = draft.payload
    other_value = encode_num((value + 1) % U32)
    controls = {
        "missing_sibling": (atomic_inputs(draft, (a,), (a_role,), (a_fields,)), [False]),
        "siblings_from_different_roots": (atomic_inputs(draft, (a, UTXO(foreign, 1)), (a_role, b_role), draft.payload),
                                         [False, False]),
        "reversed_siblings": (atomic_inputs(draft, (b, a), (b_role, a_role), (b_fields, a_fields)), [False, False]),
        "inconsistent_advance_state": (replace(draft, payload=((other_value, a_fields[1]), b_fields)), [False, True]),
        "inconsistent_decide_state": (replace(draft, payload=(a_fields, (other_value,))), [True, False]),
        "wrong_route": (with_first_output(replace(draft, payload=((a_fields[0], encode_num(1 - route)), b_fields)),
                                          contracts.terminals[1 - route]), [True, False]),
        "wrong_receipt": (replace(draft, tx=replace(draft.tx, outputs=(
            draft.tx.outputs[0], contracts.receipt(root.txid_wire(), (value + 1) % U32),
        ))), [False, False]),
    }
    rejected = {
        name: replay.record(replay.sign(candidate), candidate.previous, expected=False, input_scripts=scripts)
        for name, (candidate, scripts) in controls.items()
    }
    wrong_role = "alice" if b_role != ("alice",) else "bob"
    wrong_signer = draft.seal(lambda request: replay.keys.sign(
        replace(request, authorizer=wrong_role) if request.input_index == 1 else request,
    ))
    rejected["wrong_decide_authorizer"] = replay.record(wrong_signer, draft.previous, expected=False,
                                                       input_scripts=[True, False])
    return rejected


def request_evidence(draft):
    return [{"authorizer": request.authorizer, "input_index": request.input_index,
             "outpoint": request.outpoint.text(), "digest": request.digest.hex()}
            for request in draft.signing_requests()]


def context_controls(replay, draft, bootstrap, funding_slot):
    terminal, receipt = draft.tx.outputs
    vectors = {"outputs_reordered": (receipt, terminal), "receipt_omitted": (terminal,),
               "extra_output": (terminal, receipt, receipt)}
    controls = {name: replay.record(replay.sign(replace(draft, tx=replace(draft.tx, outputs=outputs))),
                                    draft.previous, expected=False)
                for name, outputs in vectors.items()}
    sponsor = UTXO(bootstrap, funding_slot)
    unsigned = replace(draft.tx, inputs=(*draft.tx.inputs, Input(sponsor.outpoint.txid, sponsor.vout)))
    # Sign the actual two-input transaction, while presenting the single-input context on input zero.
    roles = (draft.template.authorizers, ())
    expanded = replace(draft, tx=unsigned, previous=(*draft.previous, sponsor), payload=(*draft.payload, ()),
                       input_authorizers=roles, context_encoder=None)
    signatures = [replay.keys.sign(request) + bytes([request.sighash]) for request in expanded.signing_requests()]
    preimage = draft.preimage(0, BINDING_CODE)
    context = draft.context_encoder(preimage) if draft.context_encoder else preimage
    tx = unsigned.with_script(0, b"".join(map(push, (*reversed(signatures), context))))
    tx = FUNDING_COIN.unlock(tx, 1, bootstrap, FLAG, None)
    controls["extra_input"] = replay.record(tx, expanded.previous, expected=False, input_scripts=(False, True))
    return controls


def run_path(replay, program, source, mode, current, bootstrap, slot, *, foreign_slot=None,
             context_layout=None, context_control_slot=None, sighash_family="forkid"):
    contracts = WorkflowContracts(program, replay.keys.public, current, mode=mode,
                                  target=replay.target, optimization=replay.optimization,
                                  context_layout=context_layout, sighash_family=sighash_family)
    first, second = program.stages
    value, = evaluate(first.word, current)
    route, = evaluate(second.word, value)
    root, deployment = replay.deploy(contracts, bootstrap, slot)
    done = {"deploy": root}
    rows = {"deploy": deployment}
    controls, rebind, foreign_rows = {}, None, {}
    if mode == "serial":
        version = replay.versions[slot % len(replay.versions)]
        first_draft = contracts.prepare(first.name, done, version=version)
        if foreign_slot is not None:
            controls.update(first_controls(replay, contracts, first_draft, root, value))
        parent = replay.sign_work(first_draft)
        rows[first.name] = replay.record_step(first_draft, parent)
        rows[first.name]["signing_requests"] = request_evidence(first_draft)
        done[first.name] = parent
        if parent.outputs != (contracts.state_output(root.txid_wire(), value),):
            raise ValueError("the intermediate output differs from the host state")
        final = second.name
    else:
        final = mode
    version = replay.versions[(slot + 1) % len(replay.versions)]
    draft = contracts.prepare(final, done, version=version)
    if foreign_slot is not None:
        other_root, foreign_rows["deploy"] = replay.deploy(contracts, bootstrap, foreign_slot)
        if mode == "atomic":
            controls = atomic_controls(replay, contracts, draft, root, other_root, value, route)
        elif mode == "serial":
            foreign_done = {"deploy": other_root}
            other_draft = contracts.prepare(first.name, foreign_done, version=first_draft.tx.version)
            foreign_done[first.name] = replay.sign_work(other_draft)
            foreign_rows[first.name] = replay.record(foreign_done[first.name], other_draft.previous)
            if foreign_done[first.name].outputs != (contracts.state_output(other_root.txid_wire(), value),):
                raise ValueError("the foreign control does not carry the same numeric state")
            rejected, rebind = second_controls(replay, contracts, draft, done, first_draft, foreign_done, value, route)
            controls.update(rejected)
    if mode == "fused" and current == 19 and first.owner != second.owner:
        wrong = draft.seal(lambda request: replay.keys.sign(
            replace(request, authorizer=first.owner) if request.authorizer == second.owner else request,
        ))
        controls["wrong_decide_authorizer"] = replay.record(wrong, draft.previous, expected=False)
    if context_control_slot is not None:
        controls.update(context_controls(replay, draft, bootstrap, context_control_slot))
    tx = replay.sign_work(draft) if mode == "serial" else replay.sign(draft)
    rows[final] = replay.record_step(draft, tx)
    rows[final]["signing_requests"] = request_evidence(draft)
    if tx.outputs != (contracts.terminals[route], contracts.receipt(root.txid_wire(), value)):
        raise ValueError("the verified outputs differ from the host state and route")
    artifact = contracts.artifact(source)
    result = {
        "artifact_sha256": artifact["artifact_sha256"], "current": current, "next": value,
        "route": ("review", "settle")[route], "replay_check": "passed",
        "transactions": rows, **metrics(tuple(rows.values()), artifact),
    }
    result["estimated_minus_measured_bytes"] = {
        key: artifact["estimated_cost"][key] - result[key] for key in ("whole_path_bytes", "max_transaction_bytes")
    }
    if controls:
        result.update(rejections=controls, rebind=rebind, foreign_control_transactions=foreign_rows)
    return artifact, result


def recovery_setup(replay, contracts, bootstrap, slot):
    root, deployment = replay.deploy(contracts, bootstrap, slot)
    done, rows = {"deploy": root}, {"deploy": deployment}
    if contracts.plan.mode == "serial":
        first = contracts.plan.templates[0].name
        draft = contracts.prepare(first, done, version=replay.versions[0])
        done[first] = replay.sign_work(draft)
        rows[first] = replay.record(done[first], draft.previous)
        rows[first]["signing_requests"] = request_evidence(draft)
    final = contracts.plan.templates[-1]
    normal = contracts.prepare(final.name, done)
    return done, rows, normal, contracts.prepare_refund(final.inputs[0], done, version=replay.versions[0])


def recovery_race(replay, contracts, prepared, *, refund_wins):
    done, rows, normal, refund = prepared
    before = snapshot(replay, contracts, done)
    tx = replay.sign_work(normal) if contracts.plan.mode == "serial" else replay.sign(normal)
    exit_tx = replay.sign_work(refund)
    candidates = (("continue", normal, tx), ("refund", refund, exit_tx))
    proofs = {name: valid_with_live_inputs(replay, draft, spend) for name, draft, spend in candidates}
    winner, loser = reversed(candidates) if refund_wins else candidates
    name, draft, spend = winner
    rows[name] = replay.record(spend, draft.previous)
    other_name, other_draft, other_spend = loser
    rows[f"{other_name}_after_{name}"] = replay.record(other_spend, other_draft.previous, expected=False, live_only=True)
    after = snapshot(replay, contracts, done)
    if refund_wins and contracts.plan.mode == "atomic":
        if after["advance"] or len(after["refund"]) != 1:
            raise ValueError("atomic race did not leave precisely one refundable sibling")
        sibling = contracts.prepare_refund(ParentOutput("deploy", 1), done)
        rows["refund_remaining_sibling"] = replay.record(replay.sign_work(sibling), sibling.previous)
    final = snapshot(replay, contracts, done)
    if final["advance"] or final["refund"]:
        raise ValueError("workflow race left live contract outputs")
    return {"winner": name, "both_valid_with_live_inputs": proofs, "transactions": rows,
            "states": {"before": before, "after_conflict": after, "terminal": final}}


def replay_recovery(replay, source, bootstrap, slots, *, declared_recovery=None, source_path=None):
    deadline = (replay.node.call("getblockcount", []) + 9 if declared_recovery is None
                else declared_recovery.height)
    extended = source + f"\nrecovery: {deadline} review ;\n".encode() if declared_recovery is None else source
    program = SourceCompiler(extended.decode(), source_path=source_path).workflow()
    serial, atomic = (WorkflowContracts(program, replay.keys.public, 19, mode=mode, target=replay.target,
                                        optimization=replay.optimization) for mode in ("serial", "atomic"))
    early_slot, exit_slot, serial_slot, atomic_slot = slots
    early_done, early_rows, _, early_draft = recovery_setup(replay, serial, bootstrap, early_slot)
    before = snapshot(replay, serial, early_done)
    early_rows["early_refund"] = early_refund(replay, early_draft)
    exit_done, exit_rows, _, refund = recovery_setup(replay, serial, bootstrap, exit_slot)
    serial_race = recovery_setup(replay, serial, bootstrap, serial_slot)
    atomic_race = recovery_setup(replay, atomic, bootstrap, atomic_slot)
    tip = replay.node.call("getblockcount", [])
    if tip < deadline:
        replay.node.call("generate", [deadline - tip])
    # This path signs only the first stage and then refunds with the recovery role.
    exit_before = snapshot(replay, serial, exit_done)
    refund_rejections = refund_controls(replay, refund)
    exit_rows["refund"] = replay.record(replay.sign_work(refund), refund.previous)
    exit_after = snapshot(replay, serial, exit_done)
    artifacts = {mode: contracts.artifact(extended) for mode, contracts in (("serial", serial), ("atomic", atomic))}
    return artifacts, {
        "source": extended.decode(), "locktime": deadline,
        "early_refund": {"artifact_sha256": artifacts["serial"]["artifact_sha256"],
                         "before": before, "transactions": early_rows},
        "second_signer_absent": {"artifact_sha256": artifacts["serial"]["artifact_sha256"],
                                 "before": exit_before, "transactions": exit_rows, "after": exit_after,
                                 "rejections": refund_rejections},
        "decide_wins": {"artifact_sha256": artifacts["serial"]["artifact_sha256"],
                        **recovery_race(replay, serial, serial_race, refund_wins=False)},
        "atomic_refund_wins": {"artifact_sha256": artifacts["atomic"]["artifact_sha256"],
                               **recovery_race(replay, atomic, atomic_race, refund_wins=True)},
    }


def decision_evidence(replay, program, source, current, paths, sighash_family):
    options = dict(source_bytes=source, search=True, target=replay.target, optimization=replay.optimization,
                   sighash_family=sighash_family)
    first = program.stages[0]
    _, path_bytes = compile_workflow(program, replay.keys.public, current, **options)
    _, peak = compile_workflow(program, replay.keys.public, current, objective="peak-validation", **options)
    cap = path_bytes["candidates"]["fused"]["cost"]["max_transaction_bytes"]
    _, budget = compile_workflow(program, replay.keys.public, current, objective="peak-validation",
                                 max_tx_bytes=cap, **options)
    _, late = compile_workflow(program, replay.keys.public, current, available_authorizers=(first.owner,), **options)
    reports = {"path_bytes": path_bytes, "peak_validation": peak, "peak_with_byte_budget": budget, "first_signer_only": late}
    for report in reports.values():
        for mode, row in report["candidates"].items():
            if "artifact_sha256" not in row:
                continue
            name = next(key for key, path in paths.items() if path["current"] == current and key.endswith("/" + mode))
            path = paths[name]
            if row.get("artifact_sha256") == path["artifact_sha256"]:
                row["replay"] = {
                    "path": name, "status": path["replay_check"], "route": path["route"],
                    **{key: path[key] for key in (
                        "whole_path_bytes", "max_transaction_bytes", "estimated_minus_measured_bytes",
                        "max_node_rpc_median_ms", "max_chain_gang_median_ms", "max_stack_payload_bytes",
                    )},
                }
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET)
    parser.add_argument("--sighash-family", choices=SIGHASH_FAMILY_OPTIONS, default="forkid")
    parser.add_argument("--optimize", choices=OPTIMIZATIONS, default="stack")
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--compare-forkid-context", action="store_true", help="also replay full-context baselines")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")
    chronicle = args.sighash_family != "forkid"
    if chronicle and (args.compare_forkid_context or args.target == "forkid-v1"):
        parser.error("Chronicle replay requires a Chronicle spend target and has no full ForkID context")
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the Chronicle-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("the replay requires a fresh peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    replay = Replay(node, args.samples, args.target, activation, args.optimize)
    source = args.source.read_bytes()
    program = SourceCompiler(source.decode(), source_path=args.source).workflow()
    if program.independent:
        parser.error("--source must permit all layouts so the replay can compare them before adding independent-submit")
    if chronicle and program.recovery:
        parser.error("Chronicle replay currently requires a workflow without recovery")
    modes = ("fused", "serial") if chronicle else WORKFLOW_MODES
    foreign_slot = len(modes) * len(CASES)
    independent_slot = foreign_slot + 2
    recovery_slots = range(independent_slot + 1, independent_slot + 5)
    sponsor_slot = recovery_slots.stop
    baseline_cases = tuple((name, current, mode) for name, current in CASES for mode in ("fused", "serial"))
    bootstrap = replay.fund(sponsor_slot + 1 + (len(baseline_cases) if args.compare_forkid_context else 0))
    builds, paths = {}, {}
    for index, (name, current) in enumerate(CASES):
        for offset, mode in enumerate(modes):
            control = {"serial": foreign_slot, "atomic": foreign_slot + 1}.get(mode) if name == "at-threshold" else None
            sponsor = sponsor_slot if mode == "fused" and name == "at-threshold" and program.recovery is None else None
            artifact, path = run_path(replay, program, source, mode, current, bootstrap, len(modes) * index + offset,
                                      foreign_slot=control, context_control_slot=sponsor, sighash_family=args.sighash_family)
            builds[artifact["artifact_sha256"]] = artifact
            paths[f"{name}/{mode}"] = path
        if len({(paths[f"{name}/{mode}"]["next"], paths[f"{name}/{mode}"]["route"]) for mode in modes}) != 1:
            raise ValueError(f"workflow layouts disagree for {name}")
    decisions = {label: decision_evidence(replay, program, source, current, paths, args.sighash_family)
                 for label, current in (("review", 7), ("settle", 19))}
    constrained_source = source + f"\nindependent-submit: {program.stages[0].name} ;\n".encode()
    constrained = SourceCompiler(constrained_source.decode(), source_path=args.source).workflow()
    constrained_spec, constrained_report = compile_workflow(
        constrained, replay.keys.public, 19, source_bytes=constrained_source, target=replay.target,
        optimization=replay.optimization, search=True, sighash_family=args.sighash_family,
    )
    artifact, path = run_path(replay, constrained, constrained_source, constrained_report["selected"],
                              19, bootstrap, independent_slot, sighash_family=args.sighash_family)
    if artifact != constrained_spec:
        raise ValueError("independent-submit replay used a different build")
    builds[artifact["artifact_sha256"]] = artifact
    paths["independent-submit/serial"] = path
    constrained_report.update(source=constrained_source.decode(), replay_path="independent-submit/serial")
    recovery = None
    if not chronicle:
        recovery_artifacts, recovery = replay_recovery(replay, source, bootstrap, recovery_slots,
                                                      declared_recovery=program.recovery, source_path=args.source)
        builds.update((item["artifact_sha256"], item) for item in recovery_artifacts.values())
    baselines = {}
    if args.compare_forkid_context:
        for index, (name, current, mode) in enumerate(baseline_cases, sponsor_slot + 1):
            artifact, path = run_path(replay, program, source, mode, current, bootstrap, index, context_layout="full")
            builds[artifact["artifact_sha256"]] = artifact
            chosen = paths[f"{name}/{mode}"]
            if (path["next"], path["route"]) != (chosen["next"], chosen["route"]):
                raise ValueError("ForkID layouts disagree on the verified result")
            baselines[f"{name}/{mode}"] = {
                "baseline": path, "selected_artifact_sha256": chosen["artifact_sha256"],
                "path_bytes_saved": path["whole_path_bytes"] - chosen["whole_path_bytes"],
            }
    report = {
        "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "schema_version": 1,
        "source": source.decode(), "target": args.target, "sighash_family": args.sighash_family, "sample_count": args.samples,
        "bsv_node_version": node.version, "chain_gang": engine, "activation_height": activation,
        "regtest_profile": os.environ["SCRIPT_LAB_REGTEST_PROFILE"],
        "bootstrap_raw": bootstrap.serialize().hex(),
        "fixture_public_keys": {role: key.hex() for role, key in replay.keys.public.items()},
        "artifacts": builds, "paths": paths, "decisions": decisions,
        "independent_submit": constrained_report, "recovery": recovery,
    }
    if args.compare_forkid_context:
        report["forkid_context_baselines"] = baselines
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

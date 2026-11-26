"""Replay block-height recovery and join conflicts on a funded peerless regtest."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path

from compiler import PROJECT_NAME, PROJECT_VERSION, parse, schedule
from protocol import DEFAULT_TARGET, JOIN_WITNESSES, TARGETS, UTXO, build_artifact
from replay import EXAMPLE, TASK_ID, Replay
from shared.benchmark_admission import submit_and_mine
from shared.benchmark_validation import ACTIVATION_HEIGHT, CONTEXT_PIN, Node, RPCError, chain_metadata
from shared.chain_gang import validate_at_heights

HEIGHT = 145
DATA = {"x": 10, "y": 5}


def snapshot(replay, contracts, done):
    live = []
    for ref in contracts.recovery_refs():
        if ref.step in done:
            utxo = UTXO(done[ref.step], ref.vout)
            if replay.node.call("gettxout", [utxo.parent.txid(), utxo.vout]) is not None:
                live.append(utxo.outpoint)
    return contracts.recovery_status(done, live, tip_height=replay.node.call("getblockcount", []))


def workflow(replay, contracts, bootstrap, slot, *, both=True):
    deploy, deployment = replay.deploy(contracts, bootstrap, slot)
    done, records = {"deploy": deploy}, {"deploy": deployment}
    states = {"deployed": snapshot(replay, contracts, done)}
    records["split"] = replay.branch(contracts, "split", done, {})
    states["split"] = snapshot(replay, contracts, done)
    a, b = contracts.plan.program.work
    records[a.name] = replay.branch(contracts, a.name, done, DATA, version=replay.versions[0])
    states["one_result"] = snapshot(replay, contracts, done)
    if both:
        records[b.name] = replay.branch(contracts, b.name, done, DATA)
        states["both_results"] = snapshot(replay, contracts, done)
    return done, records, states


def valid_with_live_inputs(replay, draft, tx):
    height = replay.node.call("getblockcount", []) + 1
    creation = tuple(replay.traces[utxo.parent.txid()]["height"] for utxo in draft.previous)
    context = dict(spend_height=height, activation_height=replay.activation_height, utxo_heights=creation)
    node = replay.node.verdicts(tx, draft.parents, timeout_us=50_000, **context)
    validate_at_heights(tx, draft.parents, **context)
    if not all(node):
        raise ValueError("expected the transaction to verify with all its inputs")
    return {"node_scripts": node, "chain_gang": True, **context}


def early_refund(replay, draft):
    tx = replay.sign(draft)
    proof = valid_with_live_inputs(replay, draft, tx)
    node = replay.node
    if proof["spend_height"] > tx.locktime:
        raise ValueError("early-refund control ran after its deadline")
    accepted = node.call("sendrawtransaction", [tx.serialize().hex()])
    if accepted != tx.txid() or accepted not in node.call("getrawnonfinalmempool", []):
        raise ValueError("future transaction did not enter the nonfinal pool")
    if accepted in node.call("getrawmempool", []):
        raise ValueError("early refund entered the ordinary mempool")
    block_id, = node.call("generate", [1])
    block = node.call("getblock", [block_id])
    if accepted in block["tx"] or node.call("gettxout", [draft.previous[0].parent.txid(), draft.previous[0].vout]) is None:
        raise ValueError("early refund spent its input")
    return {"txid": accepted, "raw": tx.serialize().hex(), **proof, "nonfinal_pool": True,
            "ordinary_mempool": False, "mined": False, "block_height": block["height"]}


def queued_refund_conflict(replay, join):
    tx = replay.sign(join)
    proof = valid_with_live_inputs(replay, join, tx)
    admission = submit_and_mine(replay.node, tx)
    if admission.get("rpc_code") != -26 or "txn-mempool-conflict" not in admission.get("rpc_message", ""):
        raise ValueError("expected a local admission conflict with the queued refund")
    return {"raw": tx.serialize().hex(), **proof, "admission": admission}


def queued_status(node, original):
    txid = original["txid"]
    tip = node.call("getblockcount", [])
    if txid not in node.call("getrawnonfinalmempool", []):
        raise ValueError("expected the earlier refund to remain queued on the pinned node")
    try:
        node.call("sendrawtransaction", [original["raw"]])
    except RPCError as error:
        if error.code == -27:
            return {"tip_height": tip, "nonfinal_pool": True, "resubmit_rpc_code": error.code,
                    "resubmit_rpc_message": error.message}
        raise
    raise ValueError("expected this node to recognize the resubmission as a duplicate")


def refund_controls(replay, draft):
    tx = draft.tx
    owner, = draft.template.authorizers
    wrong_role = "operator" if owner != "operator" else "alice"
    controls = {
        "lower_locktime": replay.sign(replace(draft, tx=replace(tx, locktime=0))),
        "final_sequence": replay.sign(replace(draft, tx=replace(tx, inputs=(replace(tx.inputs[0], sequence=0xffffffff),)))),
        "wrong_amount": replay.sign(replace(draft, tx=replace(tx, outputs=(replace(tx.outputs[0], value=tx.outputs[0].value - 1),)))),
        "wrong_signer": draft.seal(lambda request: replay.keys.sign(replace(request, authorizer=wrong_role))),
    }
    return {name: replay.record(spend, draft.previous, expected=False) for name, spend in controls.items()}


def race(replay, contracts, done, records, states, *, winner):
    join = contracts.prepare(contracts.plan.program.join_name, done)
    refund = contracts.prepare_refund(contracts.plan.program.work[0].name, done, version=replay.versions[0])
    join_tx, refund_tx = replay.sign(join), replay.sign(refund)
    if refund_tx.inputs[0].outpoint() not in [item.outpoint() for item in join_tx.inputs]:
        raise ValueError("race must contend on one result outpoint")
    states["timeout"] = snapshot(replay, contracts, done)
    candidate = {"join": (join, join_tx), "refund": (refund, refund_tx)}
    valid = {name: valid_with_live_inputs(replay, draft, tx) for name, (draft, tx) in candidate.items()}
    first, second = ("join", "refund") if winner == "join" else ("refund", "join")
    first_draft, first_tx = candidate[first]
    second_draft, second_tx = candidate[second]
    records[first] = replay.record_step(first_draft, first_tx)
    records[f"{second}_after_{first}"] = replay.record(second_tx, second_draft.previous, expected=False, live_only=True)
    states["after_conflict"] = snapshot(replay, contracts, done)
    if winner == "refund":
        other = contracts.prepare_refund(contracts.plan.program.work[1].name, done)
        records["refund_other_result"] = replay.record_step(other, replay.sign(other))
    states["terminal"] = snapshot(replay, contracts, done)
    if states["terminal"]["advance"] or states["terminal"]["refund"]:
        raise ValueError("race left live workflow outputs")
    return {"winner": winner, "both_valid_before_race": valid, "states": states, "records": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET)
    parser.add_argument("--join-witness", choices=JOIN_WITNESSES, default="shared")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("recovery replay requires the height-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("recovery replay requires an empty peerless regtest")
    activation = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", ACTIVATION_HEIGHT))
    replay = Replay(node, 3, args.target, activation, "stack", args.join_witness)
    source = EXAMPLE.read_bytes() + f"\nrecovery: {HEIGHT} review ;\n".encode()
    contracts = replay.contracts(schedule(parse(source.decode()), "split"))
    a, b = contracts.plan.program.work
    bootstrap = replay.fund(5)

    done, records, states = workflow(replay, contracts, bootstrap, 0)
    normal = contracts.prepare(contracts.plan.program.join_name, done)
    records["join"] = replay.record(replay.sign(normal), normal.previous)
    states["terminal"] = snapshot(replay, contracts, done)

    missing, missing_records, missing_states = workflow(replay, contracts, bootstrap, 1, both=False)
    result = contracts.prepare_refund(a.name, missing, version=replay.versions[0])
    queued, queued_records, queued_states = workflow(replay, contracts, bootstrap, 4)
    early = early_refund(replay, contracts.prepare_refund(a.name, queued, version=replay.versions[0]))
    early_conflict = queued_refund_conflict(replay, contracts.prepare(contracts.plan.program.join_name, queued))
    races = [workflow(replay, contracts, bootstrap, slot) for slot in (2, 3)]
    before = node.call("getblockcount", [])
    if before >= HEIGHT:
        raise ValueError("fixture reached timeout before preparing the competition")
    node.call("generate", [HEIGHT - before])
    controls = refund_controls(replay, result)
    missing_states["timeout"] = snapshot(replay, contracts, missing)
    missing_records["refund_result"] = replay.record(replay.sign(result), result.previous)
    missing_states["after_result_refund"] = snapshot(replay, contracts, missing)
    unfinished = contracts.prepare_refund("split", missing, vout=1)
    missing_records["refund_unfinished_work"] = replay.record(replay.sign(unfinished), unfinished.previous)
    missing_states["terminal"] = snapshot(replay, contracts, missing)

    join_wins = race(replay, contracts, *races[0], winner="join")
    refund_wins = race(replay, contracts, *races[1], winner="refund")
    queued_states["after_timeout"] = snapshot(replay, contracts, queued)
    queued_after_timeout = queued_status(node, early)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "report": "recovery",
        "target": args.target, "bsv_node_version": node.version, "chain_gang": engine,
        "activation_height": activation, "source": source.decode(), "bootstrap_raw": bootstrap.serialize().hex(),
        "fixture_public_keys": {name: key.hex() for name, key in replay.keys.public.items()},
        "task_id": TASK_ID.hex(), "build": build_artifact(contracts.describe(), source),
        "normal_join": {"states": states, "records": records},
        "early_refund": {"queued": early, "join_admission": early_conflict, "after_timeout": queued_after_timeout,
                         "states": queued_states, "records": queued_records},
        "missing_branch": {"states": missing_states, "records": missing_records, "controls": controls,
                           "absent_worker": b.name},
        "join_wins": join_wins, "refund_wins": refund_wins,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

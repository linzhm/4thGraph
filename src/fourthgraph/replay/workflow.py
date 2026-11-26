"""Compile the example and replay both schedules on a fresh peerless BSV regtest."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path

from fourthgraph._paths import CHECKOUT

from fourthgraph.benchmark.admission import submit_and_mine
from fourthgraph.benchmark.cases import native_coin, seed
from fourthgraph.benchmark.validation import ACTIVATION_HEIGHT, CONTEXT_PIN, Node, chain_metadata, timed
from fourthgraph.bsv.chain_gang import validate_at_heights
from fourthgraph.bsv.evaluate import evaluate as evaluate_script
from fourthgraph.bsv.script import encode_num
from fourthgraph.bsv.transaction import Input, Transaction

from fourthgraph.compiler.source import PROJECT_NAME, PROJECT_VERSION, CompileError, Word, evaluate, parse, schedule
from fourthgraph.compiler.lowering import BASELINE, OPTIMIZATIONS
from fourthgraph.workflow.protocol import DEFAULT_TARGET, JOIN_WITNESSES, TARGETS, Contracts, FLAG, Host, ROOT_VALUE, UTXO
from fourthgraph.workflow.protocol import OBJECTIVES, compile_decision, compile_search, invalidated
from fourthgraph.compiler.wordsets import HOST_WORDS

EXAMPLE = CHECKOUT / "projects/workflow-examples/example.fth"
GATED_EXAMPLE = CHECKOUT / "projects/workflow-examples/gated.fth"
TASK_ID = seed("forth/task-id")
SOURCE = native_coin("forth/deployment", ROOT_VALUE + 10_000, p2pk=True)


def host_call(name, host, value):
    op = HOST_WORDS[name]
    result, = evaluate(Word(op.takes, op.gives, (op,), op.location), value, context=host)
    return result


class TestKeys:
    """Deterministic fixture keys shared across cases. Never use them for real funds."""

    def __init__(self):
        from ecdsa import SECP256k1, SigningKey

        self.keys = {name: SigningKey.from_secret_exponent(
            1 + int.from_bytes(seed("forth/" + name), "big") % (SECP256k1.order - 1), curve=SECP256k1,
        ) for name in ("operator", "alice", "bob", "review", "settle")}
        self.public = {name: key.verifying_key.to_string("compressed") for name, key in self.keys.items()}

    def sign(self, request):
        from ecdsa.util import sigencode_der_canonize

        return self.keys[request.authorizer].sign_digest_deterministic(
            request.digest, hashfunc=sha256, sigencode=sigencode_der_canonize,
        )


def stack_peaks(tx, previous):
    peaks = {"main_payload_bytes": 0, "alt_payload_bytes": 0, "combined_payload_bytes": 0}

    def observe(main, alt):
        main_bytes, alt_bytes = sum(map(len, main)), sum(map(len, alt))
        for field, value in zip(peaks, (main_bytes, alt_bytes, main_bytes + alt_bytes), strict=True):
            peaks[field] = max(peaks[field], value)

    for txin, utxo in zip(tx.inputs, previous, strict=True):
        main, alt = evaluate_script(txin.script, observe_stack=observe)
        if alt:
            raise ValueError("development evaluator left data in scriptSig altstack")
        main, alt = evaluate_script(utxo.output.script, main, lambda _sig, _pk: True, observe_stack=observe)
        if main != [b"\x01"] or alt:
            raise ValueError("development evaluator did not finish on the one-item success stack")
    return peaks


class Replay:
    def __init__(self, node, samples, target, activation_height, optimization=BASELINE, join_witness="full"):
        self.node = node
        self.samples = samples
        self.target = target
        self.optimization = optimization
        self.join_witness = join_witness
        self.versions, _ = TARGETS[target]
        self.version = self.versions[-1]
        self.activation_height = activation_height
        self.keys = TestKeys()
        self.known = {}
        self.host = Host(self.lookup, self.keys.sign, self.submit)
        self.traces = {}

    def contracts(self, plan):
        return Contracts(plan, self.keys.public, TASK_ID, target=self.target,
                         optimization=self.optimization, join_witness=self.join_witness)

    def lookup(self, outpoint):
        utxo = UTXO(self.known[outpoint.txid], outpoint.vout)
        result = self.node.call("gettxout", [outpoint.txid[::-1].hex(), outpoint.vout])
        if result is None or result["scriptPubKey"]["hex"] != utxo.output.script.hex():
            raise ValueError(f"could not look up live output {outpoint.text()}")
        return utxo

    def submit(self, tx):
        admitted = submit_and_mine(self.node, tx)
        self.traces[tx.txid()] = admitted
        if admitted["mined"]:
            self.known[tx.txid_wire()] = tx
            return tx.txid_wire()
        return b""

    def fund(self, cells, *, coin=SOURCE):
        self.node.call("generate", [101])
        outputs = (coin.output,) * cells
        raw = Transaction((), outputs, version=self.version).serialize().hex()
        funded = self.node.call("fundrawtransaction", [raw, {"changePosition": cells, "feeRate": 0.00002}])
        signed = self.node.call("signrawtransaction", [funded["hex"]])
        if not signed["complete"]:
            raise ValueError("regtest could not sign the shared bootstrap transaction")
        bootstrap = Transaction.parse(bytes.fromhex(signed["hex"]))
        if bootstrap.version != self.version or bootstrap.outputs[:cells] != outputs or not self.submit(bootstrap):
            raise ValueError(f"regtest could not mine the shared bootstrap: {self.traces.get(bootstrap.txid())}")
        return bootstrap

    def deploy(self, contracts, bootstrap, slot, *, version=None, coin=SOURCE):
        utxo = UTXO(bootstrap, slot)
        version = contracts.version if version is None else version
        outputs = getattr(contracts, "deployment_outputs", (contracts.root,))
        tx = Transaction((Input(utxo.outpoint.txid, slot),), outputs, version=version)
        tx = coin.unlock(tx, 0, bootstrap, FLAG, None)
        return tx, self.record(tx, (utxo,))

    def sign(self, draft, host=None):
        host = self.host if host is None else host
        return draft.seal(lambda request: host_call("bsv-sign", host, request))

    def record(self, tx, previous, *, expected=True, live_only=False, input_scripts=None):
        if Transaction.parse(tx.serialize()) != tx:
            raise ValueError("transaction serialization round trip failed")
        parents = tuple(utxo.parent for utxo in previous)
        if any(txin.outpoint() != Input(utxo.outpoint.txid, utxo.vout).outpoint()
               for txin, utxo in zip(tx.inputs, previous, strict=True)):
            raise ValueError("replay input does not match its recorded previous output")
        chain_parents = []
        missing = []
        spent_parents = set()
        for utxo in previous:
            if live_only and self.node.call("gettxout", [utxo.parent.txid(), utxo.vout]) is None:
                missing.append(utxo.outpoint.text())
                spent_parents.add(utxo.parent.txid_wire())
            else:
                host_call("bsv-lookup-utxo", self.host, utxo.outpoint)
                chain_parents.append(utxo.parent)
        if live_only and len(missing) != 1:
            raise ValueError(f"missing-result control expected one absent outpoint, found {missing}")
        spend_height = self.node.call("getblockcount", []) + 1
        # Give the hypothetical parent in the missing-UTXO control the next block height.
        heights = tuple(self.traces.get(parent.txid(), {}).get("height", spend_height) for parent in parents)
        context = dict(spend_height=spend_height, activation_height=self.activation_height, utxo_heights=heights)

        def chain_check():
            try:
                validate_at_heights(tx, chain_parents, **context)
            except (ValueError, RuntimeError) as error:
                return False, str(error)
            return True, None

        samples = self.samples if expected else 0
        node, node_ms = timed(lambda: self.node.verdicts(tx, parents, timeout_us=50_000, **context), samples)
        (chain, chain_error), chain_ms = timed(chain_check, samples)
        mined = bool(host_call("bsv-submit", self.host, tx))
        admission = self.traces[tx.txid()]
        expected_code = None if expected else (-25 if live_only else -26)
        expected_scripts = [expected or live_only] * len(tx.inputs) if input_scripts is None else list(input_scripts)
        # chain-gang receives complete parent transactions. A live sibling can
        # supply the historical bytes of a spent output from the same parent.
        chain_has_spent_parent = live_only and spent_parents <= {parent.txid_wire() for parent in chain_parents}
        if (node != expected_scripts or chain != (expected or chain_has_spent_parent) or mined != expected
                or admission["mempool"] != expected or admission.get("rpc_code") != expected_code):
            raise ValueError(f"unexpected verdict for {tx.txid()}: scripts={node}, chain-gang={chain}, "
                             f"admission={admission}")
        return {
            "txid": tx.txid(), "raw": tx.serialize().hex(), "transaction_version": tx.version,
            "previous": [utxo.outpoint.text() for utxo in previous],
            "output_scripts": [output.script.hex() for output in tx.outputs],
            "bytes": len(tx.serialize()),
            "validation_context": context,
            "bsv_node": {"input_scripts": node, "verify_rpc_median_ms": node_ms, **admission},
            "chain_gang": {"transaction": chain, "median_ms": chain_ms, "error": chain_error,
                           "missing_outpoints": missing, "all_inputs_live": not missing},
            "stack": stack_peaks(tx, previous) if expected else None,
        }

    def sign_work(self, draft):
        owner, = draft.template.authorizers

        def owner_only(request):
            if request.authorizer != owner:
                raise ValueError(f"{owner} has no access to {request.authorizer}'s signer")
            return self.keys.sign(request)

        return self.sign(draft, replace(self.host, sign=owner_only))

    def record_step(self, draft, tx):
        binding = draft.binding_evidence(tx)
        return {**self.record(tx, draft.previous), "binding": binding}

    def branch(self, contracts, name, done, data, *, version=None, controls=None):
        draft = contracts.prepare(name, done, data, version=version)
        layout = contracts.output_layout(name)
        if controls is not None and layout is not None and layout.committed:
            outputs = list(draft.tx.outputs)
            slot = layout.committed[-1]
            value = layout.read(outputs[slot])
            outputs[slot] = layout.bind(value ^ 1)[slot]
            inconsistent = replace(draft, tx=replace(draft.tx, outputs=tuple(outputs)))
            controls[name + "_wrong_shared_input"] = self.record(self.sign(inconsistent), draft.previous,
                                                                 expected=False)
        work = draft.template.outputs == ("result", "data")
        tx = self.sign_work(draft) if work else self.sign(draft)
        done[name] = tx
        return {**self.record_step(draft, tx), "authorizers": list(draft.template.authorizers)}

    def false_gate(self, contracts, name, done, data, version):
        draft = contracts.prepare(name, done, data, version=version)
        fields = list(draft.payload[0])
        gate_input = contracts.plan.program.gate.input
        fields[contracts.external_inputs(draft.template).index(gate_input)] = encode_num((1 << 32) - 1)
        invalid = replace(draft, payload=(tuple(fields),))
        return self.record(self.sign(invalid), invalid.previous, expected=False)

    def controls(self, contracts, join, foreign_result):
        one = replace(join, tx=replace(join.tx, inputs=join.tx.inputs[:1]), previous=join.previous[:1],
                      payload=join.payload[:1])
        missing_input = self.record(self.sign(one), one.previous, expected=False)
        # Build the intentionally invalid transaction outside the normal binding API.
        foreign = UTXO(foreign_result, 0)
        foreign_input = replace(join.tx.inputs[1], txid=foreign.outpoint.txid)
        fields = contracts.join_payload((join.previous[0].parent, foreign.parent))
        bad_origin = replace(join, tx=replace(join.tx, inputs=(join.tx.inputs[0], foreign_input)),
                             previous=(join.previous[0], foreign), payload=(fields, fields))
        wrong_split = self.record(self.sign(bad_origin), bad_origin.previous, expected=False)
        reversed_parents = tuple(reversed(join.previous))
        reversed_fields = contracts.join_payload(tuple(item.parent for item in reversed_parents))
        bad_slots = replace(join, tx=replace(join.tx, inputs=tuple(reversed(join.tx.inputs))),
                            previous=reversed_parents, payload=(reversed_fields, reversed_fields))
        wrong_slots = self.record(self.sign(bad_slots), bad_slots.previous, expected=False)
        wrong_output, = (item for item in contracts.terminals if item != join.tx.outputs[0])
        bad_route = replace(join, tx=replace(join.tx, outputs=(wrong_output,)))
        wrong_successor = self.record(self.sign(bad_route), bad_route.previous, expected=False)
        other_version = {"forkid-v1": 2, "chronicle-v2": 1, "both": 3}[self.target]
        bad_version = replace(join, tx=replace(join.tx, version=other_version))
        wrong_version = self.record(self.sign(bad_version), bad_version.previous, expected=False)
        return {"missing_input": missing_input, "wrong_split_same_task_id": wrong_split, "wrong_slots": wrong_slots,
                "wrong_successor": wrong_successor, "wrong_version": wrong_version}

    def path(self, plan, bootstrap, slot, data, route, *, foreign=None):
        c = plan if isinstance(plan, Contracts) else self.contracts(plan)
        plan = c.plan
        first_version, second_version = self.versions[0], self.versions[-1]
        if route == "review":
            first_version, second_version = second_version, first_version
        root, funding = self.deploy(c, bootstrap, slot, version=second_version)
        done = {"deploy": root}
        records = {"deploy": funding}
        controls = {}
        rebinding = {}
        gate = plan.program.gate
        if plan.mode == "fused":
            if gate is not None:
                controls["false_gate"] = self.false_gate(c, "fused", done, data, first_version)
            records["fused"] = self.branch(c, "fused", done, data, version=first_version)
        else:
            a, b = plan.program.work
            if gate is not None:
                gate_tx = gate.name if gate.name in c.templates else "split"
                controls["false_gate"] = self.false_gate(c, gate_tx, done, data, second_version)
                if gate_tx != "split":
                    records[gate.name] = self.branch(c, gate.name, done, data, version=second_version, controls=controls)
            records["split"] = self.branch(c, "split", done, data, version=second_version, controls=controls)
            left, right = (b, a) if route == "review" else (a, b)
            versions = {a.name: first_version, b.name: second_version}
            left_data = {key: data[key] for key in c.external_inputs(c.templates[left.name])}
            right_data = {key: data[key] for key in c.external_inputs(c.templates[right.name])}
            records[left.name] = self.branch(c, left.name, done, left_data, version=versions[left.name])
            right_draft = c.prepare(right.name, done, right_data, version=versions[right.name])
            done[right.name] = self.sign_work(right_draft)
            join = c.prepare(plan.program.join_name, done, version=first_version)
            if foreign:
                # Signed bytes for both branches exist, but the right parent is still absent on chain.
                missing = self.record(
                    self.sign(join), join.previous, expected=False, live_only=True,
                )
                if missing["chain_gang"]["missing_outpoints"] != [UTXO(done[right.name], 0).outpoint.text()]:
                    raise ValueError("missing-result control recorded a different absent branch")
                controls["missing_from_utxo_set"] = missing
            records[right.name] = {**self.record_step(right_draft, done[right.name]),
                                   "authorizers": list(right_draft.template.authorizers)}
            if foreign:
                controls.update(self.controls(c, join, foreign))
            records[join.template.name] = self.record_step(join, self.sign(join))
            split = done["split"]
            split_draft = c.prepare("split", done, data, version=split.version)
            replacement = replace(split_draft, tx=replace(split_draft.tx, locktime=split.locktime + 1))
            rebound = self.sign(replacement)
            rebinding = {"old_split_txid": split.txid(), "replacement_split_txid": rebound.txid(),
                         "descendant_authorizers": invalidated(plan, "split", split, rebound)}
        last = records[plan.templates[-1].name]
        expected_script = c.terminals[route == "settle"].script.hex()
        if last["output_scripts"] != [expected_script]:
            raise ValueError(f"replay did not reach {route}")
        return {"data": data, "route": route, "steps": records, "metrics": metrics(plan, records),
                "controls": controls, "authorizations_to_refresh_after_split_changes": rebinding}


def metrics(plan, records):
    depths = {"deploy": 1}
    for step in plan.templates:
        depths[step.name] = 1 + max(depths[parent.step] for parent in step.inputs)
    work_result_refs = {p for step in plan.templates for p in step.inputs if p.step != "deploy"}
    return {
        "whole_path_bytes": sum(row["bytes"] for row in records.values()),
        "post_deployment_bytes": sum(row["bytes"] for name, row in records.items() if name != "deploy"),
        "max_transaction_bytes": max(row["bytes"] for row in records.values()),
        "transaction_count": len(records),
        "dependency_depth_including_deploy": max(depths.values()),
        "dependency_depth_after_deploy": max(depths.values()) - 1,
        "intermediate_utxos": len(work_result_refs),
        "peak_stack": {key: max(row["stack"][key] for row in records.values()) for key in records["deploy"]["stack"]},
        "max_single_transaction_chain_gang_median_ms": max(row["chain_gang"]["median_ms"] for row in records.values()),
        "max_single_transaction_bsv_verify_rpc_median_ms": max(row["bsv_node"]["verify_rpc_median_ms"] for row in records.values()),
    }


def search_replay(replay, source, *, join_witness, objective, available_data=None, available_authorizers=None):
    program = parse(source.decode())
    contracts, plans, decision = compile_search(
        program, replay.keys.public, TASK_ID, source_bytes=source, target=replay.target,
        optimization=replay.optimization, join_witness=join_witness, objective=objective,
        available_data=available_data, available_authorizers=available_authorizers,
    )
    # Every split layout gets a foreign result with exactly the same covenant.
    # Dedicate separate funding outputs to all distinct paths.
    bootstrap = replay.fund(2 * len(contracts) + sum(c.plan.mode == "split" for c in contracts.values()))
    gate_data = {program.gate.input: 2} if program.gate is not None else {}
    cases, foreign = {}, {}
    spare = 2 * len(contracts)
    for name, contract in contracts.items():
        foreign_result = None
        if contract.plan.mode == "split":
            deploy, deployment = replay.deploy(contract, bootstrap, spare)
            spare += 1
            done = {"deploy": deploy}
            records = {"deploy": deployment}
            if contract.separate_gate:
                gate = program.gate.name
                records[gate] = replay.branch(contract, gate, done, gate_data)
            records["split"] = replay.branch(contract, "split", done, gate_data)
            right = program.work[1]
            records[right.name] = replay.branch(contract, right.name, done, {right.input: 5})
            foreign_result = done[right.name]
            foreign[name] = records
        for route, data in (("settle", {"x": 10, "y": 5}), ("review", {"x": (1 << 32) - 1, "y": 2})):
            row = replay.path(contract, bootstrap, len(cases), {**data, **gate_data}, route, foreign=foreign_result)
            cases[f"{name}_{route}"] = {"scenario": "original", "candidate": name,
                                       "source_sha256": plans[name]["source_sha256"],
                                       "artifact_sha256": plans[name]["artifact_sha256"], **row}
    return {"schema_version": 3, "bootstrap_raw": bootstrap.serialize().hex(), "source": source.decode(),
            "plans": plans, "decisions": {"original": decision}, "foreign_same_task_id": foreign, "cases": cases}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--samples", type=int, default=7)
    cli.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET)
    cli.add_argument("--optimize", choices=OPTIMIZATIONS, default=BASELINE)
    cli.add_argument("--join-witness", choices=JOIN_WITNESSES)
    cli.add_argument("--topology", choices=("parallel", "gated-parallel"), default="parallel")
    cli.add_argument("--search", action="store_true", help="replay both routes for every eligible candidate")
    cli.add_argument("--objective", choices=OBJECTIVES)
    cli.add_argument("--available-data", nargs="*")
    cli.add_argument("--available-authorizers", nargs="*")
    args = cli.parse_args()
    if args.samples < 1:
        cli.error("--samples must be positive")
    if not args.search and (args.objective or args.available_data is not None or args.available_authorizers is not None):
        cli.error("--objective and availability options require --search")
    from tx_engine import Tx

    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN or not hasattr(Tx, "validate_with_chronicle_context"):
        raise ValueError(f"the replay requires the explicit height-aware chain-gang pin: {engine}")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getconnectioncount", []) or node.call("getblockcount", []):
        raise ValueError("replay requires an empty peerless regtest")
    activation = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", ACTIVATION_HEIGHT))
    replay = Replay(node, args.samples, args.target, activation, args.optimize, args.join_witness or "full")
    example = GATED_EXAMPLE if args.topology == "gated-parallel" else EXAMPLE
    source = example.read_bytes()
    if args.search:
        result = search_replay(replay, source, join_witness=args.join_witness, objective=args.objective or "path-bytes",
                               available_data=args.available_data, available_authorizers=args.available_authorizers)
    else:
        result = baseline_replay(replay, source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "project": PROJECT_NAME, "compiler_version": PROJECT_VERSION, "sample_count": args.samples,
        "bsv_node_version": node.version, "chain_gang": engine,
        "regtest_profile": os.environ.get("SCRIPT_LAB_REGTEST_PROFILE"),
        "target": args.target, "topology": args.topology, "optimization": args.optimize,
        "join_witness": args.join_witness or ("all" if args.search else "full"),
        "chronicle_activation_height": activation,
        "task_id": TASK_ID.hex(),
        "fixture_public_keys": {name: key.hex() for name, key in replay.keys.public.items()},
        **result,
    }, indent=2) + "\n")


def baseline_replay(replay, source):
    pp = parse(source.decode())
    constrained_step = pp.gate.name if pp.gate is not None else "a"
    constrained_source = source + f"\nindependent-submit: {constrained_step} ;\n".encode()
    independent = parse(constrained_source.decode())
    options = dict(mode="auto", target=replay.target, optimization=replay.optimization, join_witness=replay.join_witness)
    fused_and_split, original_plans, original_decision = compile_decision(
        pp, replay.keys.public, TASK_ID, source_bytes=source, **options,
    )
    constrained, constrained_plans, constrained_decision = compile_decision(
        independent, replay.keys.public, TASK_ID, source_bytes=constrained_source, **options,
    )
    try:
        schedule(independent, "fused")
    except CompileError as err:
        rejected = str(err)
    else:
        raise ValueError("hard independent submission boundary did not block fusion")
    bootstrap = replay.fund(7)
    c = fused_and_split["split"]
    other, deployment = replay.deploy(c, bootstrap, 6)
    foreign = {"deploy": other}
    gate_input = {pp.gate.input: 2} if pp.gate is not None else {}
    split_row = replay.branch(c, "split", foreign, gate_input)
    b_row = replay.branch(c, "b", foreign, {"y": 5})
    plans = {**original_plans, "constrained": constrained_plans["split"]}
    cases = {}
    for plan_id, contract in (*fused_and_split.items(), ("constrained", constrained["split"])):
        scenario = "constrained" if plan_id == "constrained" else "original"
        for route, data in (("settle", {"x": 10, "y": 5}), ("review", {"x": (1 << 32) - 1, "y": 2})):
            control = foreign["b"] if contract.plan.mode == "split" else None
            row = replay.path(contract, bootstrap, len(cases), {**data, **gate_input}, route, foreign=control)
            cases[f"{plan_id}_{route}"] = {
                "scenario": scenario, "candidate": contract.plan.mode,
                "source_sha256": plans[plan_id]["source_sha256"], "artifact_sha256": plans[plan_id]["artifact_sha256"],
                **row,
            }
    return {
        "schema_version": 2, "bootstrap_raw": bootstrap.serialize().hex(),
        "source": source.decode(), "constrained_source": constrained_source.decode(),
        "plans": plans, "decisions": {"original": original_decision, "constrained": constrained_decision},
        "constrained_auto_schedule": constrained_decision["selected"], "constrained_fused_error": rejected,
        "foreign_same_task_id": {"deploy": deployment, "split": split_row, "b": b_row},
        "cases": cases,
    }


if __name__ == "__main__":
    main()

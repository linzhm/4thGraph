"""Compile the example and replay both schedules on a fresh peerless BSV regtest."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path

from shared.benchmark_admission import submit_and_mine
from shared.benchmark_cases import native_coin, seed
from shared.benchmark_validation import ACTIVATION_HEIGHT, CONTEXT_PIN, Node, chain_metadata, timed
from shared.chain_gang import validate_at_heights
from shared.evaluate import evaluate as evaluate_script
from shared.transaction import Input, Transaction

from compiler import CompileError, HOST_WORDS, Word, evaluate, parse, schedule
from protocol import DEFAULT_TARGET, TARGETS, Contracts, FLAG, Host, ROOT_VALUE, UTXO, invalidated

EXAMPLE = Path(__file__).with_name("example.fth")
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
    def __init__(self, node, samples, target, activation_height):
        self.node = node
        self.samples = samples
        self.target = target
        self.version, _ = TARGETS[target]
        self.activation_height = activation_height
        self.keys = TestKeys()
        self.known = {}
        self.host = Host(self.lookup, self.keys.sign, self.submit)
        self.traces = {}

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

    def fund(self, cells):
        self.node.call("generate", [101])
        outputs = (SOURCE.output,) * cells
        raw = Transaction((), outputs, version=self.version).serialize().hex()
        funded = self.node.call("fundrawtransaction", [raw, {"changePosition": cells, "feeRate": 0.00002}])
        signed = self.node.call("signrawtransaction", [funded["hex"]])
        if not signed["complete"]:
            raise ValueError("regtest could not sign the shared bootstrap transaction")
        bootstrap = Transaction.parse(bytes.fromhex(signed["hex"]))
        if bootstrap.version != self.version or bootstrap.outputs[:cells] != outputs or not self.submit(bootstrap):
            raise ValueError(f"regtest could not mine the shared bootstrap: {self.traces.get(bootstrap.txid())}")
        return bootstrap

    def deploy(self, contracts, bootstrap, slot):
        utxo = UTXO(bootstrap, slot)
        tx = Transaction((Input(utxo.outpoint.txid, slot),), (contracts.root,), version=contracts.version)
        tx = SOURCE.unlock(tx, 0, bootstrap, FLAG, None)
        return tx, self.record(tx, (utxo,))

    def sign(self, draft, host=None):
        host = self.host if host is None else host
        return draft.seal(lambda request: host_call("sign", host, request))

    def record(self, tx, previous, *, expected=True, live_only=False):
        if Transaction.parse(tx.serialize()) != tx:
            raise ValueError("transaction serialization round trip failed")
        parents = tuple(utxo.parent for utxo in previous)
        if any(txin.outpoint() != Input(utxo.outpoint.txid, utxo.vout).outpoint()
               for txin, utxo in zip(tx.inputs, previous, strict=True)):
            raise ValueError("replay input does not match its recorded previous output")
        if expected:
            for utxo in previous:
                host_call("lookup-utxo", self.host, utxo.outpoint)
        spend_height = self.node.call("getblockcount", []) + 1
        # Give the hypothetical parent in the missing-UTXO control the next block height.
        heights = tuple(self.traces.get(parent.txid(), {}).get("height", spend_height) for parent in parents)
        context = dict(spend_height=spend_height, activation_height=self.activation_height, utxo_heights=heights)
        chain_parents = parents[:1] if live_only else parents

        def chain_check():
            try:
                validate_at_heights(tx, chain_parents, **context)
            except (ValueError, RuntimeError) as error:
                return False, str(error)
            return True, None

        samples = self.samples if expected else 0
        node, node_ms = timed(lambda: self.node.verdicts(tx, parents, **context), samples)
        (chain, chain_error), chain_ms = timed(chain_check, samples)
        mined = bool(host_call("submit", self.host, tx))
        if (all(node), chain, mined) != (expected or live_only, expected, expected):
            raise ValueError(f"unexpected verdict for {tx.txid()}: scripts={node}, chain-gang={chain}, "
                             f"admission={self.traces[tx.txid()]}")
        return {
            "txid": tx.txid(), "raw": tx.serialize().hex(), "transaction_version": tx.version,
            "previous": [utxo.outpoint.text() for utxo in previous],
            "output_scripts": [output.script.hex() for output in tx.outputs],
            "bytes": len(tx.serialize()),
            "validation_context": context,
            "bsv_node": {"input_scripts": node, "verify_rpc_median_ms": node_ms, **self.traces[tx.txid()]},
            "chain_gang": {"transaction": chain, "median_ms": chain_ms, "error": chain_error},
            "stack": stack_peaks(tx, previous) if expected else None,
        }

    def sign_work(self, draft):
        owner, = draft.template.authorizers

        def owner_only(request):
            if request.authorizer != owner:
                raise ValueError(f"{owner} has no access to {request.authorizer}'s signer")
            return self.keys.sign(request)

        return self.sign(draft, replace(self.host, sign=owner_only))

    def branch(self, contracts, name, done, data):
        draft = contracts.prepare(name, done, data)
        work = draft.template.outputs == ("result", "data")
        tx = self.sign_work(draft) if work else self.sign(draft)
        done[name] = tx
        return {**self.record(tx, draft.previous), "authorizers": list(draft.template.authorizers)}

    def controls(self, contracts, done, join, foreign_result):
        one = replace(join, tx=replace(join.tx, inputs=join.tx.inputs[:1]), previous=join.previous[:1],
                      payload=join.payload[:1])
        missing_input = self.record(self.sign(one), one.previous, expected=False)
        bad_origin = contracts.prepare(join.template.name, {**done, contracts.plan.program.work[1].name: foreign_result})
        wrong_split = self.record(self.sign(bad_origin), bad_origin.previous, expected=False)
        wrong_output, = (item for item in contracts.terminals if item != join.tx.outputs[0])
        bad_route = replace(join, tx=replace(join.tx, outputs=(wrong_output,)))
        wrong_successor = self.record(self.sign(bad_route), bad_route.previous, expected=False)
        other_version = 1 if join.tx.version == 2 else 2
        bad_version = replace(join, tx=replace(join.tx, version=other_version))
        wrong_version = self.record(self.sign(bad_version), bad_version.previous, expected=False)
        return {"missing_input": missing_input, "wrong_split_same_task_id": wrong_split,
                "wrong_successor": wrong_successor, "wrong_version": wrong_version}

    def path(self, plan, bootstrap, slot, data, route, *, foreign=None):
        c = Contracts(plan, self.keys.public, TASK_ID, target=self.target)
        root, funding = self.deploy(c, bootstrap, slot)
        done = {"deploy": root}
        records = {"deploy": funding}
        controls = {}
        rebinding = {}
        if plan.mode == "fused":
            records["fused"] = self.branch(c, "fused", done, data)
        else:
            a, b = plan.program.work
            records["split"] = self.branch(c, "split", done, None)
            left, right = (b, a) if route == "review" else (a, b)
            records[left.name] = self.branch(c, left.name, done, {left.input: data[left.input]})
            right_draft = c.prepare(right.name, done, {right.input: data[right.input]})
            done[right.name] = self.sign_work(right_draft)
            join = c.prepare(plan.program.join_name, done)
            if foreign:
                # Signed bytes for both branches exist, but the right parent is still absent on chain.
                controls["missing_from_utxo_set"] = self.record(
                    self.sign(join), join.previous, expected=False, live_only=True,
                )
            records[right.name] = {**self.record(done[right.name], right_draft.previous),
                                   "authorizers": list(right_draft.template.authorizers)}
            if foreign:
                controls.update(self.controls(c, done, join, foreign))
            records[join.template.name] = self.record(self.sign(join), join.previous)
            split = done["split"]
            split_draft = c.prepare("split", done)
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
        "transaction_count": len(records),
        "dependency_depth_including_deploy": max(depths.values()),
        "dependency_depth_after_deploy": max(depths.values()) - 1,
        "intermediate_utxos": len(work_result_refs),
        "peak_stack": {key: max(row["stack"][key] for row in records.values()) for key in records["deploy"]["stack"]},
        "max_single_transaction_chain_gang_median_ms": max(row["chain_gang"]["median_ms"] for row in records.values()),
        "max_single_transaction_bsv_verify_rpc_median_ms": max(row["bsv_node"]["verify_rpc_median_ms"] for row in records.values()),
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--samples", type=int, default=7)
    cli.add_argument("--target", choices=TARGETS, default=DEFAULT_TARGET)
    args = cli.parse_args()
    if args.samples < 1:
        cli.error("--samples must be positive")
    from tx_engine import Tx

    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN or not hasattr(Tx, "validate_with_chronicle_context"):
        raise ValueError(f"the replay requires the explicit height-aware chain-gang pin: {engine}")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getconnectioncount", []) or node.call("getblockcount", []):
        raise ValueError("replay requires an empty peerless regtest")
    activation = int(os.environ.get("SCRIPT_LAB_CHRONICLE_HEIGHT", ACTIVATION_HEIGHT))
    replay = Replay(node, args.samples, args.target, activation)
    source = EXAMPLE.read_text()
    pp = parse(source)
    fused, split = schedule(pp, "fused"), schedule(pp, "split")
    independent = parse(source + "\na independent-submit\n")
    constrained = schedule(independent)
    try:
        schedule(independent, "fused")
    except CompileError as err:
        rejected = str(err)
    else:
        raise ValueError("hard independent submission boundary did not block fusion")
    bootstrap = replay.fund(5)
    c = Contracts(split, replay.keys.public, TASK_ID, target=args.target)
    other, deployment = replay.deploy(c, bootstrap, 4)
    foreign = {"deploy": other}
    split_row = replay.branch(c, "split", foreign, None)
    b_row = replay.branch(c, "b", foreign, {"y": 5})
    cases = {
        "fused_settle": replay.path(fused, bootstrap, 0, {"x": 10, "y": 5}, "settle"),
        "fused_review": replay.path(fused, bootstrap, 1, {"x": (1 << 32) - 1, "y": 2}, "review"),
        "split_settle": replay.path(split, bootstrap, 2, {"x": 10, "y": 5}, "settle", foreign=foreign["b"]),
        "split_review": replay.path(constrained, bootstrap, 3, {"x": (1 << 32) - 1, "y": 2}, "review"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "schema_version": 1, "sample_count": args.samples, "bsv_node_version": node.version, "chain_gang": engine,
        "regtest_profile": os.environ.get("SCRIPT_LAB_REGTEST_PROFILE"),
        "target": args.target, "chronicle_activation_height": activation,
        "task_id": TASK_ID.hex(), "bootstrap_raw": bootstrap.serialize().hex(),
        "fixture_public_keys": {name: key.hex() for name, key in replay.keys.public.items()},
        "source": source, "constrained_source": source + "\na independent-submit\n",
        "plans": {plan.mode: Contracts(plan, replay.keys.public, TASK_ID, target=args.target).describe()
                  for plan in (fused, split)},
        "constrained_auto_schedule": constrained.mode, "constrained_fused_error": rejected,
        "foreign_same_task_id": {"deploy": deployment, "split": split_row, "b": b_row},
        "cases": cases,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()

"""Independent engine replay and project acceptance collection."""
from base64 import b64encode
from collections import Counter
from dataclasses import replace
from hashlib import sha256
from importlib.metadata import distribution
import json
from pathlib import Path
from statistics import median
from time import perf_counter_ns
import unittest
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from fourthgraph.bsv.evaluate import ScriptError, evaluate
from fourthgraph.bsv.transaction import Transaction

CONTEXT_PIN = "74676b9c002c452e7f21a9ed9265f4972bef03f6"
CORE_PIN = "8b60b71a12a69fdcb465d3e627dbf6f43d6ed081"
ACTIVATION_HEIGHT = 2
UTXO_HEIGHT = 3
SPEND_HEIGHT = 4
# These regtest fixtures are post-Genesis at both creation and spend.
NODE_GENESIS_FLAGS = sum(1 << bit for bit in (1, 2, 3, 16, 18, 19))
NODE_CHRONICLE = 1 << 20
NODE_UTXO_AFTER_CHRONICLE = 1 << 21
NODE_FLAGS = NODE_GENESIS_FLAGS | NODE_CHRONICLE | NODE_UTXO_AFTER_CHRONICLE


class RPCError(ValueError):
    def __init__(self, method, error):
        self.code = error["code"]
        self.message = error["message"]
        super().__init__(f"{method}: {self.code}: {self.message}")


class Node:
    def __init__(self, url, cookie):
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("benchmark requires a loopback regtest RPC URL")
        self.url = url
        auth = b64encode(Path(cookie).read_bytes().strip()).decode("ascii")
        self.headers = {"Authorization": "Basic " + auth, "Content-Type": "application/json"}
        if self.call("getblockchaininfo", [])["chain"] != "regtest":
            raise ValueError("benchmark requires a regtest node")
        self.version = self.call("getnetworkinfo", [])["version"]
        if self.version != 101020300:
            raise ValueError(f"expected BSV Node 1.2.3, got {self.version}")

    def call(self, method, params):
        data = json.dumps(dict(jsonrpc="1.0", id=method, method=method, params=params)).encode()
        try:
            with urlopen(Request(self.url, data, self.headers), timeout=60) as response:
                reply = json.load(response)
        except HTTPError as response:
            if response.code != 500:
                raise
            with response:
                reply = json.load(response)
        if reply["error"] is not None:
            raise RPCError(method, reply["error"])
        return reply["result"]

    def verdicts(self, tx, parents, *, spend_height=SPEND_HEIGHT, activation_height=ACTIVATION_HEIGHT,
                 utxo_heights=None, timeout_us=5000, expected_rejection=None):
        """Return input verdicts and check the exact reason for errors when specified."""
        raw = tx.serialize().hex()
        if utxo_heights is None:
            utxo_heights = (UTXO_HEIGHT,) * len(tx.inputs)
        inputs = []
        for index, (txin, parent, height) in enumerate(zip(tx.inputs, parents, utxo_heights, strict=True)):
            prevout = parent.outputs[txin.vout]
            flags = NODE_GENESIS_FLAGS
            if spend_height >= activation_height:
                flags |= NODE_CHRONICLE
            if height >= activation_height:
                flags |= NODE_UTXO_AFTER_CHRONICLE
            inputs.append(dict(tx=raw, n=index, flags=flags, reportflags=True,
                               txo=dict(lock=prevout.script.hex(), value=prevout.value, height=height)))
        result = self.call("verifyscript", [inputs, False, timeout_us])
        for row, request in zip(result, inputs, strict=True):
            if row["flags"] != request["flags"] or row["result"] not in {"ok", "error"}:
                raise ValueError(f"unexpected BSV Node result: {row}")
            if (expected_rejection is not None and row["result"] == "error"
                    and row.get("description") != expected_rejection):
                raise ValueError(f"expected BSV Node rejection {expected_rejection!r}, got {row}")
        return [row["result"] == "ok" for row in result]


def chain_metadata():
    installed = distribution("tx-engine")
    origin = json.loads(installed.read_text("direct_url.json") or "{}")
    return {"version": installed.version, "commit": origin.get("vcs_info", {}).get("commit_id")}


def chain_verdict(tx, parents):
    from tx_engine import Tx

    def engine_tx(raw):
        parsed = Tx.parse(raw)
        if parsed.serialize() != raw:
            raise ValueError("chain-gang changed the transaction framing")
        return parsed

    spend = engine_tx(tx.serialize())
    unique = {parent.txid(): parent for parent in parents}
    funding = [engine_tx(parent.serialize()) for parent in unique.values()]
    try:
        if hasattr(spend, "validate_with_chronicle_context"):
            heights = [(txin.txid[::-1].hex(), txin.vout, UTXO_HEIGHT) for txin in tx.inputs]
            spend.validate_with_chronicle_context(funding, SPEND_HEIGHT, ACTIVATION_HEIGHT, heights, True)
        else:
            # This pin exposes Chronicle-new full-input validation through validate().
            spend.validate(funding)
    except (ValueError, RuntimeError):
        return False
    return True


def timed(check, samples):
    result = check()
    elapsed = []
    for _ in range(samples):
        start = perf_counter_ns()
        observed = check()
        elapsed.append(perf_counter_ns() - start)
        if observed != result:
            raise ValueError("verification result varied between samples")
    return result, median(elapsed) / 1_000_000 if elapsed else None


def stack_profile(lock, unlock):
    """Measure the successful execution path in the development evaluator."""
    peaks = dict(main_items=0, alt_items=0, combined_payload_bytes=0)

    def observe(main, alt):
        peaks["main_items"] = max(peaks["main_items"], len(main))
        peaks["alt_items"] = max(peaks["alt_items"], len(alt))
        payload = sum(map(len, main)) + sum(map(len, alt))
        peaks["combined_payload_bytes"] = max(peaks["combined_payload_bytes"], payload)

    # Independent engines already check the transaction. Native CHECKSIG is
    # modeled as successful here to measure the remaining script's stack.
    try:
        main, alt = evaluate(unlock, observe_stack=observe)
        if alt:
            raise ScriptError("unlock left data in altstack")
        stack, alt = evaluate(lock, main, lambda _signature, _key: True, observe_stack=observe)
        if not stack or not any(stack[-1]) or alt:
            raise ScriptError("development evaluator did not finish on the success path")
    except ScriptError as error:
        return {"source": "development evaluator", "unavailable": str(error)}
    return {"source": "development evaluator; native CHECKSIG modeled as true", **peaks}


def measure_leg(leg, node, *, samples=0, profile_stack=False, check_control=False):
    tx, parents, flags = leg.tx, leg.parents, leg.flags
    raw = tx.serialize()
    if Transaction.parse(raw) != tx:
        raise ValueError("shared transaction serialization failed to round-trip")
    previous = [parent.outputs[txin.vout] for txin, parent in zip(tx.inputs, parents, strict=True)]
    if any(txin.txid != parent.txid_wire() for txin, parent in zip(tx.inputs, parents, strict=True)):
        raise ValueError("synthetic transaction does not spend the recorded parent")
    chain, timing = timed(lambda: chain_verdict(tx, parents), samples)
    node_results, node_timing = timed(lambda: node.verdicts(tx, parents), samples) if node else (None, None)
    if not chain or node_results is not None and not all(node_results):
        raise ValueError(f"positive benchmark transaction failed verification: {tx.txid()}")
    control = None
    if check_control:
        changed = replace(tx, locktime=tx.locktime + 1)
        chain_reject = chain_verdict(changed, parents)
        node_reject = node.verdicts(changed, parents) if node else None
        if chain_reject or node_reject and any(node_reject):
            raise ValueError(f"stale authorization passed after locktime changed: {tx.txid()}")
        control = {"txid": changed.txid(), "expected": False, "chain_gang": chain_reject,
                   "bsv_node": node_reject}
    return {
        "txid": tx.txid(), "transaction_version": tx.version,
        "layout": [len(tx.inputs), len(tx.outputs)], "sighashes": [f"{flag:02x}" for flag in flags],
        "transaction_bytes": len(raw),
        "fee_fixture_sats": sum(out.value for out in previous) - sum(out.value for out in tx.outputs),
        "previous_lock_bytes": [len(out.script) for out in previous],
        "previous_lock_sha256": [sha256(out.script).hexdigest() for out in previous],
        "lock_bytes": [len(out.script) for out in tx.outputs],
        "output_lock_sha256": [sha256(out.script).hexdigest() for out in tx.outputs],
        "unlock_bytes": [len(txin.script) for txin in tx.inputs],
        "expected": True, "changed_locktime_control": control,
        "chain_gang": {"transaction": chain, "median_ms": timing},
        "bsv_node": {"inputs": node_results, "median_ms": node_timing},
        "stack_input_zero": stack_profile(previous[0].script, tx.inputs[0].script)
        if profile_stack else None,
    }


class AcceptanceResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}
        self.active = set()
        self.duplicates = set()

    def record(self, case, success):
        case_id = case.id()
        if case_id in self.outcomes:
            self.duplicates.add(case_id)
        self.outcomes[case_id] = success

    def addSuccess(self, test):
        self.record(test, "pass")
        super().addSuccess(test)

    def addError(self, test, err):
        self.record(test, "error")
        super().addError(test, err)

    def addFailure(self, test, err):
        self.record(test, "fail")
        super().addFailure(test, err)

    def addSkip(self, test, reason):
        self.record(test, f"skip: {reason}")
        super().addSkip(test, reason)

    def addSubTest(self, test, subtest, err):
        self.record(subtest, "pass" if err is None else "fail")
        self.active.add(test.id())
        super().addSubTest(test, subtest, err)


def suite_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from suite_ids(test)
        else:
            yield test.id()


def acceptance(test_names, stream):
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(test_names)
    expected = list(suite_ids(suite))
    if loader.errors or not expected or len(set(expected)) != len(expected):
        raise ValueError(f"invalid project acceptance inventory: {loader.errors or expected}")
    run = unittest.TextTestRunner(stream=stream, verbosity=1, resultclass=AcceptanceResult).run(suite)
    missing = set(expected) - run.outcomes.keys() - run.active
    outcomes = Counter(run.outcomes.values())
    return {"tests": expected, "outcomes": run.outcomes, "counts": dict(outcomes),
            "missing": sorted(missing), "duplicates": sorted(run.duplicates),
            "passed": bool(run.wasSuccessful() and not missing and not run.duplicates and not run.skipped)}

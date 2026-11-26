"""Fund and compare the CCTP VK boundary layouts on one fresh BSV regtest."""

import argparse
from dataclasses import replace
from hashlib import new, sha256
import json
import os
from pathlib import Path
from statistics import median
from time import perf_counter

from ecdsa import SECP256k1, SigningKey
from forth_verifier import __file__ as reference_backend
from regtest_mint import base58check, public, sign_p2pkh
from snarkjs_adapter import load_artifacts
from verifier import verify_host

from shared.benchmark_validation import CONTEXT_PIN, Node, RPCError, chain_metadata
from shared.chain_gang import validate_at_heights
from shared.evaluate import ScriptError, evaluate
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction
from vk_boundary import Layouts, SOURCE, TERMINAL_VALUE, Witness, preimage, terminal

MODES = ("fused", "atomic", "serial")
UPSTREAM = ("zkscript-affine", "zkscript-projective")
PROOF_DIRECTORY = Path("projects/groth16/reference/testdata/4thgraph-prover/split-verified")
SAMPLES = 7


def load_cases(archive):
    paths = tuple(archive / PROOF_DIRECTORY / name
                  for name in ("python_metal.json", "alternate-public-signals.json"))
    documents = [json.loads(path.read_text()) for path in paths]
    proofs = [load_artifacts(doc["key"], doc["proof"], doc["public_signals"]) for doc in documents]
    key, signals, _ = proofs[0]
    if proofs[1][0] != key or proofs[1][1] == signals or not all(verify_host(*row) for row in proofs):
        raise ValueError("expected two valid statements for the same CCTP verification key")
    return key, tuple((signals, proof) for _, signals, proof in proofs), paths


def stack_peaks(tx, parents):
    main_peak = alt_peak = combined_peak = 0

    def observe(main, alt):
        nonlocal main_peak, alt_peak, combined_peak
        main_bytes, alt_bytes = sum(map(len, main)), sum(map(len, alt))
        main_peak = max(main_peak, main_bytes)
        alt_peak = max(alt_peak, alt_bytes)
        combined_peak = max(combined_peak, main_bytes + alt_bytes)

    try:
        for txin, parent in zip(tx.inputs, parents, strict=True):
            main, alt = evaluate(txin.script, observe_stack=observe)
            if alt:
                raise ValueError("witness left an alternate stack")
            main, alt = evaluate(parent.outputs[txin.vout].script, main, lambda *_: True, observe_stack=observe)
            if main != [b"\x01"] or alt:
                raise ValueError("development interpreter did not finish on a clean true stack")
    except ScriptError as error:
        return {"unavailable": str(error)}
    return {"main_bytes": main_peak, "alt_bytes": alt_peak, "combined_bytes": combined_peak}


class Replay:
    def __init__(self, node, activation):
        self.node, self.activation = node, activation
        # This key funds the local regtest fixture only.
        self.signer = SigningKey.from_secret_exponent(41, curve=SECP256k1)
        self.address = base58check(b"\x6f" + new("ripemd160", sha256(public(self.signer)).digest()).digest())
        self.heights = {}

    def submit(self, tx):
        if self.node.call("sendrawtransaction", [tx.serialize().hex(), True]) != tx.txid():
            raise ValueError("node returned the wrong transaction identifier")
        if tx.txid() not in self.node.call("getrawmempool", []):
            raise ValueError("transaction missing from the mempool after submission")

    def mine(self, txs):
        blockhash, = self.node.call("generatetoaddress", [1, self.address])
        block = self.node.call("getblock", [blockhash, 1])
        for tx in txs:
            if tx.txid() not in block["tx"]:
                raise ValueError(f"{tx.txid()} missing from block {blockhash}")
            self.heights[tx.txid()] = block["height"]
        return blockhash

    def deploy(self, outputs):
        blocks = self.node.call("generatetoaddress", [100 + len(outputs), self.address])
        roots = {}
        for (key, locks), block in zip(outputs.items(), blocks):
            txid = self.node.call("getblock", [block, 1])["tx"][0]
            parent = Transaction.parse(bytes.fromhex(self.node.call("getrawtransaction", [txid])))
            tx = sign_p2pkh(Transaction((Input(parent.txid_wire(), 0),), locks), parent, 0, self.signer)
            self.submit(tx)
            roots[key] = tx
        self.mine(roots.values())
        return roots

    def context(self, tx, parents):
        height = self.heights.get(tx.txid())
        if height is None:
            height = self.node.call("getblockcount", []) + 1
        return dict(spend_height=height, activation_height=self.activation,
                    utxo_heights=tuple(self.heights[parent.txid()] for parent in parents))

    def measure(self, cases):
        context = {name: self.context(tx, parents) for name, (tx, parents) in cases.items()}
        readings = {name: ([], []) for name in cases}
        order = list(cases)
        for attempt in range(SAMPLES):
            pivot = attempt % len(order)
            for name in order[pivot:] + order[:pivot]:
                tx, parents = cases[name]
                bsv, chain = readings[name]
                start = perf_counter()
                validate_at_heights(tx, parents, **context[name])
                chain.append((perf_counter() - start) * 1000)
                start = perf_counter()
                verdict = self.node.verdicts(tx, parents, timeout_us=20_000, **context[name])
                bsv.append((perf_counter() - start) * 1000)
                if verdict != [True] * len(parents):
                    raise ValueError(f"BSV Node rejected {name}: {verdict}")
        return {name: {"node_rpc_median_ms": median(bsv), "chain_gang_median_ms": median(chain)}
                for name, (bsv, chain) in readings.items()}

    def reject(self, name, tx, parents, expected_scripts=None):
        context = self.context(tx, parents)
        try:
            validate_at_heights(tx, parents, **context)
        except (RuntimeError, ValueError) as error:
            chain_error = str(error)
            if "Error evaluating the script" not in chain_error:
                raise
        else:
            raise ValueError(f"chain-gang accepted {name}")
        node_scripts = self.node.verdicts(tx, parents, timeout_us=20_000, **context)
        if all(node_scripts) or (expected_scripts is not None and node_scripts != expected_scripts):
            raise ValueError(f"unexpected BSV verdict for {name}: {node_scripts}")
        try:
            self.node.call("sendrawtransaction", [tx.serialize().hex(), True])
        except RPCError as error:
            if error.code != -26 or "script-verify-flag-failed" not in error.message:
                raise
            return {"node_scripts": node_scripts, "chain_gang": chain_error, "node_admission": error.message}
        raise ValueError(f"node admitted {name}")


def controls(layouts, first, second, wrong, roots, plans, phases):
    """Negative inputs retain live UTXOs and otherwise valid transaction framing."""
    fused, = layouts.spend("fused", roots["fused", 0], wrong)
    root = roots["atomic", 0]
    atomic, = plans["atomic", 0]
    mixed_claim = push(sha256(second.proof).digest()) + push(second.claim) + preimage(atomic, 0, root)
    unmatched = atomic.with_script(0, mixed_claim)
    other_root = roots["atomic", 1]
    crossed = replace(atomic, inputs=(Input(root.txid_wire(), 0), Input(other_root.txid_wire(), 1)))
    crossed = crossed.with_script(0, push(sha256(first.proof).digest()) + push(first.claim)
                                  + preimage(crossed, 0, root))
    crossed = crossed.with_script(1, push(first.proof) + push(first.claim) + preimage(crossed, 1, other_root))
    # Recommit the whole inconsistent proof so that the MSM path still passes.
    invalid_proof, = layouts.spend("atomic", root, wrong)
    result = {
        "fused_wrong_public": (fused, (roots["fused", 0],), [False]),
        "atomic_inconsistent_claim": (unmatched, (root, root), [False, True]),
        "atomic_cross_root": (crossed, (root, other_root), [False, False]),
        "atomic_committed_invalid_proof": (invalid_proof, (root, root), [True, False]),
    }
    serial_root = roots["serial", 0]
    stage, final = plans["serial", 0]
    changed = replace(stage, outputs=(replace(stage.outputs[0], value=stage.outputs[0].value - 1),))
    changed = changed.with_script(0, push(sha256(first.proof).digest()) + push(first.claim)
                                  + preimage(changed, 0, serial_root))
    result["serial_wrong_successor"] = changed, (serial_root,), [False]
    wrong_claim = bytes([first.claim[0] ^ 1]) + first.claim[1:]
    wrong_stage, _ = layouts.spend("serial", serial_root, replace(first, claim=wrong_claim))
    result["serial_wrong_msm_value"] = wrong_stage, (serial_root,), [False]
    if not phases:
        return result
    other_stage, _ = plans["serial", 1]
    crossed = replace(final, inputs=(Input(other_stage.txid_wire(), 0), Input(serial_root.txid_wire(), 1)))
    crossed = crossed.with_script(0, preimage(crossed, 0, other_stage))
    crossed = crossed.with_script(1, push(first.proof) + push(first.claim) + push(other_stage.serialize())
                                  + preimage(crossed, 1, serial_root))
    state_alone = Transaction((Input(stage.txid_wire(), 0),), (replace(final.outputs[0], value=10_000),))
    state_alone = state_alone.with_script(0, preimage(state_alone, 0, stage))
    # The state output itself demands the original digest and the real pairing slot.
    target = terminal(second.commitment(layouts.domain, serial_root.txid_wire()))
    changed_claim = replace(final, outputs=(target,))
    changed_claim = changed_claim.with_script(0, preimage(changed_claim, 0, stage))
    changed_claim = changed_claim.with_script(1, push(second.proof) + push(second.claim) + push(stage.serialize())
                                             + preimage(changed_claim, 1, serial_root))
    changed_predecessor = stage.with_script(0, stage.inputs[0].script + push(bytes(1)))
    stale_opening = final.with_script(1, push(first.proof) + push(first.claim)
                                     + push(changed_predecessor.serialize()) + preimage(final, 1, serial_root))
    return {
        "serial_cross_root_certificate": (crossed, (other_stage, serial_root), [False, False]),
        "serial_state_without_pairing": (state_alone, (stage,), [False]),
        "serial_valid_proof_incompatible_certificate": (changed_claim, (stage, serial_root), [False, True]),
        "serial_wrong_predecessor_bytes": (stale_opening, (stage, serial_root), [True, False]),
        "serial_forged_preimage": (replace(final, locktime=1), (stage, serial_root), [False, False]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="unpacked gamma-factor CCTP source and fixtures")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zkscript", action="store_true", help="include both upstream profiles on PYTHONPATH")
    args = parser.parse_args()
    expected_backend = args.archive / "projects/groth16/reference/forth_verifier.py"
    if Path(reference_backend).resolve() != expected_backend.resolve():
        raise ValueError("put the selected archive's projects/groth16/reference on PYTHONPATH")
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the repository's Chronicle-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("the comparison requires a fresh peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    key, proofs, paths = load_cases(args.archive)
    layouts = Layouts.compile(args.archive / "4thgraph-source", key)
    witnesses = tuple(Witness.from_proof(key, signals, proof) for signals, proof in proofs)
    wrong = Witness.from_proof(key, proofs[1][0], proofs[0][1])
    modes = MODES + (UPSTREAM if args.zkscript else ())
    locks = {mode: layouts.outputs(mode) for mode in MODES}
    if args.zkscript:
        from zkscript_baseline import ZkScript

        upstream = ZkScript(key)
        locks.update({mode: (Output(100_000, upstream.lock(mode)),) for mode in UPSTREAM})

    replay = Replay(node, activation)
    roots = replay.deploy({(mode, index): locks[mode] for mode in modes for index in range(2)})
    print("Deployed all verifier outputs.", flush=True)
    plans = {}
    for case, root in roots.items():
        mode, index = case
        if mode in MODES:
            plans[case] = layouts.spend(mode, root, witnesses[index])
        else:
            unlock = upstream.unlock(mode, *proofs[index])
            plans[case] = (Transaction((Input(root.txid_wire(), 0, unlock),),
                                       (Output(TERMINAL_VALUE, asm("OP_1")),)),)

    rejected = {name: replay.reject(name, *case)
                for name, case in controls(layouts, *witnesses, wrong, roots, plans, phases=False).items()}
    if args.zkscript:
        for mode in UPSTREAM:
            for label, signals, proof in (
                ("wrong_public", proofs[1][0], proofs[0][1]),
                ("substituted_proof_point", proofs[0][0], replace(proofs[0][1], a=proofs[0][1].c)),
            ):
                name = f"{mode}_{label}"
                tx = plans[mode, 0][0].with_script(0, upstream.unlock(mode, signals, proof))
                rejected[name] = replay.reject(name, tx, (roots[mode, 0],))
    first_phase = {(mode, index, 0): (txs[0], (roots[mode, index],) * len(txs[0].inputs))
                   for (mode, index), txs in plans.items()}
    certificates = [tx for (mode, _index, _step), (tx, _) in first_phase.items() if mode == "serial"]
    for tx in certificates:
        replay.submit(tx)
    first_block = replay.mine(certificates)
    print("Mined both MSM certificates.", flush=True)

    rejected.update({name: replay.reject(name, *case)
                     for name, case in controls(layouts, *witnesses, wrong, roots, plans, phases=True).items()})
    second_phase = {("serial", i, 1): (plans["serial", i][1], (plans["serial", i][0], roots["serial", i]))
                    for i in range(2)}
    probes = first_phase | second_phase
    timings = replay.measure(probes)
    terminal_spends = [txs[-1] for txs in plans.values()]
    for tx in terminal_spends:
        replay.submit(tx)
    last_block = replay.mine(terminal_spends)
    rows = {}
    for (mode, index), root in roots.items():
        txs = plans[mode, index]
        stages = []
        for step, tx in enumerate(txs):
            case = mode, index, step
            stages.append({
                "bytes": len(tx.serialize()), "height": replay.heights[tx.txid()], "txid": tx.txid(),
                "unlock_bytes": [len(item.script) for item in tx.inputs],
                "stack_payload": stack_peaks(tx, probes[case][1]), **timings[case],
            })
        deployment_bytes = len(root.serialize())
        row = {
            "deploy_bytes": deployment_bytes, "deploy_txid": root.txid(),
            "lock_bytes": [len(output.script) for output in root.outputs],
            "lock_sha256": [sha256(output.script).hexdigest() for output in root.outputs],
            "total_bytes": deployment_bytes + sum(stage["bytes"] for stage in stages),
            "largest_tx_bytes": max(deployment_bytes, *(stage["bytes"] for stage in stages)),
            "max_node_rpc_median_ms": max(stage["node_rpc_median_ms"] for stage in stages),
            "max_chain_gang_median_ms": max(stage["chain_gang_median_ms"] for stage in stages),
            "dependency_depth_including_deploy": len(stages) + 1,
            "intermediate_utxos": int(mode == "serial"), "stages": stages,
        }
        if mode in MODES:
            row.update(deploy_raw=root.serialize().hex(), spend_raw=[tx.serialize().hex() for tx in txs])
        rows[f"{mode}_{index + 1}"] = row
    report = {
        "bsv_node": node.version, "chain_gang": engine, "samples_per_stage": SAMPLES,
        "activation_height": activation, "profile": os.environ["SCRIPT_LAB_REGTEST_PROFILE"],
        "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
        "forth_frontend_revision": (args.archive / "4thgraph-source/REVISION").read_text().strip(),
        "proof_sha256": [sha256(path.read_bytes()).hexdigest() for path in paths],
        "certificate_block": first_block, "settlement_block": last_block,
        "zkscript": {**upstream.revisions, "modulo_threshold": 1, "max_multiplier": str(1 << 128), "extractable_inputs": 0}
        if args.zkscript else None,
        "cases": rows, "negative_cases": rejected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Mined all verified settlements and wrote the comparison.", flush=True)


if __name__ == "__main__":
    main()

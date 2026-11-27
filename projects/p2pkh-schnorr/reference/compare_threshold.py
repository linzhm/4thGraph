"""Measure MuSig2 payments and native bare ECDSA 2-of-2 on the same BSV workloads."""

import argparse
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from musig2_fixture import Policy, fixture_keys, fixture_sign
from payment import lock_for_public_key, sign_spend
from fourthgraph.benchmark.run import dump_json, summarize
from fourthgraph.benchmark.admission import admission_case
from fourthgraph.benchmark.cases import Coin, Template, workloads
from fourthgraph.benchmark.validation import CONTEXT_PIN, Node, chain_metadata, measure_leg
from fourthgraph.bsv.evaluate import evaluate
from fourthgraph.bsv.script import asm, push
from fourthgraph.bsv.transaction import CHRONICLE, Output, hash256, preimage_forkid, preimage_otda


def musig2_coin(label, value):
    keys = fixture_keys(label)
    policy = Policy(tuple(key.public_key.format() for key in keys))

    def unlock(tx, index, parent, flag, _scratch):
        def signer(digest):
            # Deterministic fixture only. Include the input identity in its nonce domain.
            nonce_label = f"{label}/{tx.inputs[index].outpoint().hex()}/{index}"
            return fixture_sign(keys, policy, nonce_label, digest)

        return sign_spend(tx, index, parent.serialize(), policy.aggregate_x, signer,
                          sighash=flag, chronicle_active=bool(flag & CHRONICLE), compress_otda=False)

    return Coin(Output(value, lock_for_public_key(policy.aggregate_x)), unlock)


def native_2of2_coin(label, value):
    keys = fixture_keys(label)
    public_keys = b"".join(push(key.public_key.format()) for key in keys)
    lock = asm("OP_2") + public_keys + asm("OP_2 OP_CHECKMULTISIG")

    def unlock(tx, index, parent, flag, _scratch):
        if flag & CHRONICLE:
            preimage = preimage_otda(tx, index, lock, flag)
        else:
            amount = parent.outputs[tx.inputs[index].vout].value
            preimage = preimage_forkid(tx, index, amount, lock, flag)
        digest = hash256(preimage)
        signatures = [key.sign(digest, hasher=None) + bytes([flag]) for key in keys]
        return tx.with_script(index, asm("OP_0") + b"".join(map(push, signatures)))

    return Coin(Output(value, lock), unlock)


TEMPLATES = {"musig2": Template(musig2_coin), "native_2of2": Template(native_2of2_coin)}


def native_stack(leg):
    first = leg.tx.inputs[0]
    lock = leg.parents[0].outputs[first.vout].script
    # The prefix only pushes items, so the peak occurs just before CHECKMULTISIG.
    if not lock.endswith(asm("OP_CHECKMULTISIG")):
        raise ValueError("expected native multisig locking script")
    main, alt = evaluate(first.script + lock[:-1])
    return {"source": "script stack immediately before native CHECKMULTISIG",
            "main_items": len(main), "alt_items": len(alt),
            "combined_payload_bytes": sum(map(len, main))}


def collect(node, samples, scratch):
    report = {}
    for name, template in TEMPLATES.items():
        cases = {}
        for case, phases in workloads(template, "2of2", scratch):
            cases[case] = {}
            for phase, leg in phases.items():
                baseline = case.endswith("/batch/2x2")
                protected = phase != "funding"
                result = measure_leg(leg, node, samples=samples if baseline else 0,
                                     profile_stack=baseline and name == "musig2", check_control=baseline)
                if baseline and name == "native_2of2":
                    result["stack_input_zero"] = native_stack(leg)
                if protected:
                    if name == "musig2":
                        payloads = [2 * (66 + 32) for _ in leg.tx.inputs]
                        rounds = 2
                    else:
                        # OP_0 plus two one-byte push opcodes are on-chain framing.
                        payloads = [len(txin.script) - 3 for txin in leg.tx.inputs]
                        rounds = 1
                    result["signer_artifacts_bytes_per_input"] = payloads
                    result["signing_rounds"] = rounds
                cases[case][phase] = result
        costs = summarize(template, "2of2", cases)
        for mode, totals in costs.items():
            lifecycle = {}
            for phase in ("direct-exit", "turnover"):
                legs = cases[f"2of2/{mode}/{phase}"].values()
                lifecycle[phase] = sum(sum(leg.get("signer_artifacts_bytes_per_input", ())) for leg in legs)
            totals["signer_artifacts_lifecycle_bytes"] = lifecycle
        report[name] = {"costs": costs, "scenarios": cases}
    return report


def admission(node, scratch):
    if os.environ.get("SCRIPT_LAB_REGTEST_PROFILE") != "default" or node.call("getconnectioncount", []):
        raise ValueError("admission requires a peerless default-profile regtest")
    if node.call("getblockcount", []) == 0:
        node.call("generate", [101])
    return {
        name: {f"{flag:02x}": admission_case(node, template, f"threshold-policy/{name}/{flag:02x}", flag, scratch)
               for flag in (0x41, 0x61)}
        for name, template in TEMPLATES.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--admission", action="store_true", help="measure funding and exit on default node policy")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.samples < 0:
        parser.error("sample count must be nonnegative")
    metadata = chain_metadata()
    if metadata["commit"] != CONTEXT_PIN:
        parser.error("install the pinned chain-gang revision from the project requirements")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    with TemporaryDirectory(prefix="script-lab-threshold-") as temp:
        scratch = Path(temp)
        report = {"profile": os.environ["SCRIPT_LAB_REGTEST_PROFILE"], "chain_gang": metadata}
        if args.admission:
            report["admission"] = admission(node, scratch)
        else:
            report["samples_per_engine"] = args.samples
            report["implementations"] = collect(node, args.samples, scratch)
    if args.output:
        dump_json(args.output, report)
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

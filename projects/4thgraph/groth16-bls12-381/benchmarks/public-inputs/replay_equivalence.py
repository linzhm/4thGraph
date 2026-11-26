"""Replay a shared scalar contract against the pinned nChain affine verifiers."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
from types import SimpleNamespace

from replay_comparison import affine_controls, native_profiles
from replay_vk_boundary import Replay, load_cases, stack_peaks
from elliptic_curves.util.zkscript import unrolled_multiplication_gradients
from zkscript_baseline import BLS12_381, Groth16UnlockingKey, ZkScript, bls12_381, g1, g2

from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.chain_gang import validate_at_heights
from shared.script import asm, push
from shared.transaction import Input, Output, Transaction

MAXIMUM = 1 << 128
LOCK_VALUE = 100_000
SETTLEMENT = Output(75_000, asm("OP_1"))


def boundary_cases():
    """Public algebraic fixtures, with known relationships, for regtest only."""
    g1 = BLS12_381.g1_curve.get_generator()
    g2 = BLS12_381.g2_curve.get_generator().to_list()
    twist = tuple(tuple(g2[i:i + 2]) for i in (0, 2))

    def point(scalar):
        return tuple(g1.multiply(scalar).to_list())

    key = SimpleNamespace(alpha=point(7), beta=twist, gamma=twist, delta=twist,
                          ic=tuple(map(point, (5, 2, 3))))
    signals = ((0, 0), (1, 0), (MAXIMUM - 1, MAXIMUM - 1), (MAXIMUM, 0), (0, MAXIMUM))
    # e(A,Q) = e([7 + (5 + 2*s + 3*t) + 11]P, Q).
    return key, tuple(((s, t), SimpleNamespace(a=point(23 + 2*s + 3*t), b=twist, c=point(11)))
                      for s, t in signals)


def build_cases(key, proofs):
    profiles = native_profiles(key, proofs, input_sources=[{"max": str(MAXIMUM)}] * (len(key.ic) - 1))
    locks = {name: bytes.fromhex(entry["artifact"]["script_hex"]) for name, entry in profiles.items()}
    witnesses = {(name, i): bytes.fromhex(entry["witness"][str(i)])
                 for name, entry in profiles.items() for i in range(len(proofs))}
    upstream = {
        "nchain-affine-lock-gradients": ZkScript(key),
        "nchain-affine-witness-gradients": ZkScript(key, modulo_threshold=1600, gradients_in_witness=True),
    }
    for name, model in upstream.items():
        locks[name] = model.lock("zkscript-affine")
        for i, (signals, proof) in enumerate(proofs):
            if any(signals):
                witnesses[name, i] = model.unlock("zkscript-affine", signals, proof)
            else:
                witnesses[name, i] = zero_witness(model, signals, proof)
    return locks, witnesses, upstream, profiles


def zero_witness(model, signals, proof):
    """Use nChain's documented omitted-gradient encoding for addition with identity."""
    a, b, c = g1(proof.a), g2(proof.b), g1(proof.c)
    vk = model.cache
    engine = BLS12_381.miller_loop_engine
    b_gradients = unrolled_multiplication_gradients(engine.val_miller_loop, b, engine.exp_miller_loop)
    inverse = BLS12_381.miller_loop([a, vk.vk.gamma_abc[0], c], [b, vk.minus_gamma, vk.minus_delta]).invert()
    key = Groth16UnlockingKey.from_data(
        groth16_model=bls12_381, pub=list(signals), A=a.to_list(), B=b.to_list(), C=c.to_list(),
        gradients_pairings=[b_gradients.as_data(), model.key.gradients_minus_gamma, model.key.gradients_minus_delta],
        gradients_multiplications=[[] for _ in signals], max_multipliers=model.max_multipliers,
        gradients_additions=[[] for _ in signals[1:]], inverse_miller_output=inverse.to_list(),
        gradient_gamma_abc_zero=[], has_precomputed_gradients=model.gradients_in_witness,
    )
    return key.to_unlocking_script(bls12_381, True, 0).raw_serialize()


def run_suite(replay, key, proofs, *, measure):
    locks, witnesses, upstream, native = build_cases(key, proofs)
    roots = replay.deploy({case: (Output(LOCK_VALUE, locks[case[0]]),) for case in witnesses})
    spends = {
        (name, index): (Transaction((Input(parent.txid_wire(), 0, witnesses[name, index]),), (SETTLEMENT,)),
                        (parent,))
        for (name, index), parent in roots.items()
    }
    rejects = crossed_statements(replay, spends, witnesses, proofs, upstream, native) if measure else {}
    timings = replay.measure(spends) if measure else {}
    if not measure:
        for tx, parents in spends.values():
            context = replay.context(tx, parents)
            validate_at_heights(tx, parents, **context)
            if replay.node.verdicts(tx, parents, timeout_us=20_000, **context) != [True]:
                raise ValueError(f"BSV Node rejected a shared-domain boundary case: {tx.txid()}")
    for tx, _ in spends.values():
        replay.submit(tx)
    block = replay.mine(tx for tx, _ in spends.values())
    cases = {}
    for (name, index), (tx, (parent,)) in spends.items():
        deploy_bytes, spend_bytes = len(parent.serialize()), len(tx.serialize())
        cases[f"{name}_{index + 1}"] = {
            "signals": list(map(str, proofs[index][0])),
            "script_sha256": sha256(locks[name]).hexdigest(), "lock_bytes": len(locks[name]),
            "witness_bytes": len(witnesses[name, index]), "total_bytes": deploy_bytes + spend_bytes,
            "deployment_bytes": deploy_bytes, "spend_bytes": spend_bytes,
            "stack_payload": stack_peaks(tx, (parent,)), "txid": tx.txid(),
            "bsv_node": True, "chain_gang": True, "height": replay.heights[tx.txid()],
            **timings.get((name, index), {}),
        }
        if name.startswith("nchain-") and not any(proofs[index][0]):
            cases[f"{name}_{index + 1}"]["witness_encoder"] = "upstream-low-level-omit-identity-gradient"
    return {"settlement_block": block, "cases": cases, "rejections": rejects,
            "nchain_revisions": next(iter(upstream.values())).revisions}


def crossed_statements(replay, spends, witnesses, proofs, upstream, native):
    rejects = {}
    for (name, index), (tx, parents) in spends.items():
        swapped = 1 - index
        if name in upstream:
            witness = upstream[name].unlock("zkscript-affine", proofs[swapped][0], proofs[index][1])
            controls = {"crossed_statement_with_valid_msm": witness}
        else:
            profile = native[name]
            artifact = profile["artifact"]
            packet, other_packet = (bytes.fromhex(profile["packets"][str(i)]) for i in (index, swapped))
            witness, other = witnesses[name, index], witnesses[name, swapped]
            prefix = witness[:-len(push(packet))]
            controls = {"crossed_statement": prefix + push(other_packet)}
            if name.startswith("4thgraph-affine-"):
                controls.update(affine_controls(artifact, witness, other, packet, other_packet))
            else:
                claim_end = len(other) - len(push(other_packet))
                claim_bytes = artifact["vk_claim_bytes"]
                controls["crossed_statement_with_valid_msm"] = (
                    prefix[:-claim_bytes] + other[claim_end - claim_bytes:claim_end] + push(other_packet)
                )
        for control, witness in controls.items():
            label = f"{name}_{index + 1}_{control}"
            rejects[label] = replay.reject(label, tx.with_script(0, witness), parents, [False])
    return rejects


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--archive", type=Path, required=True, help="prepared CCTP reference")
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the Chronicle-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("the comparison requires a fresh peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    replay = Replay(node, activation)
    key, proofs, paths = load_cases(args.archive)
    cctp = run_suite(replay, key, proofs, measure=True)
    print(f"CCTP profiles mined {len(cctp['cases'])} spends and rejected {len(cctp['rejections'])} controls.", flush=True)
    edges = run_suite(replay, *boundary_cases(), measure=False)
    print(f"Scalar boundary profiles mined {len(edges['cases'])} spends.", flush=True)
    report = {
        "maximum_inclusive": str(MAXIMUM), "node_version": node.version, "chain_gang": engine,
        "regtest_profile": os.environ["SCRIPT_LAB_REGTEST_PROFILE"], "activation_height": activation,
        "cctp_fixture_sha256": [sha256(path.read_bytes()).hexdigest() for path in paths],
        "cctp": cctp, "scalar_boundaries": edges,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

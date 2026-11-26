"""Replay dynamic CCTP proof inputs with 4thGraph, hand-written CCTP, and nChain."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from forth_verifier import FORTH_SOURCE, build_unlock, compile_verifier
from replay_vk_boundary import Replay, SAMPLES, load_cases, stack_peaks
from zkscript_baseline import ZkScript

from shared.benchmark_validation import CONTEXT_PIN, Node, chain_metadata
from shared.script import asm, number, push
from shared.transaction import Input, Output, Transaction, preimage_all

FORTH_VERIFIER = Path(__file__).resolve().parents[2]
PROJECT = FORTH_VERIFIER.parent
ROOT = PROJECT.parents[1]
TERMINAL_VALUE = 75_000
CCTP_COMPACT_SHA256 = "196ad323cd359b46bd7fbdf16fe486aaf7e09fea869edddefebc34082743650b"
CCTP_WINDOWED_SHA256 = "e797549499d4ef9857afb1e29471099a058a67b15c2f94d5e7895e4aa39d257f"


def affine_g1(point):
    return list((*point, 1) if point is not None else (0, 1, 0))


def affine_g2(point):
    return [list(pair) for pair in (*point, (1, 0))]


def native_profiles(key, proofs, *, input_sources=None, script_era="genesis"):
    metadata = {"protocol": "groth16", "curve": "bls12381"}
    material = {
        "script_era": script_era,
        "key": {**metadata, "nPublic": len(key.ic) - 1, "IC": [affine_g1(point) for point in key.ic],
                "vk_alpha_1": affine_g1(key.alpha), "vk_beta_2": affine_g2(key.beta),
                "vk_gamma_2": affine_g2(key.gamma), "vk_delta_2": affine_g2(key.delta)},
        "cases": [{"signals": list(map(str, signals)),
                   "proof": {**metadata, "pi_a": affine_g1(proof.a), "pi_b": affine_g2(proof.b),
                             "pi_c": affine_g1(proof.c)}} for signals, proof in proofs],
    }
    if input_sources is not None:
        material["input_sources"] = input_sources
    # Both compilers have a module named compiler.py. The native compiler
    # runs with only the lab and its own project on the import path.
    with TemporaryDirectory(prefix="groth16-inputs-") as directory:
        fixture, output = (Path(directory) / name for name in ("normalized.json", "native.json"))
        fixture.write_text(json.dumps(material) + "\n")
        subprocess.run([sys.executable, str(Path(__file__).with_name("generate_native.py")),
                        str(fixture), str(output)], check=True, cwd=ROOT,
                       env={**os.environ, "PYTHONPATH": os.pathsep.join(map(str, (ROOT, PROJECT, FORTH_VERIFIER)))})
        return json.loads(output.read_text())


def public_state(packet):
    return Output(TERMINAL_VALUE, push(b"\0" + packet) + asm("OP_DROP OP_1"))


def affine_controls(artifact, witness, other, packet, other_packet):
    def flip(offset):
        return witness[:offset] + bytes([witness[offset] ^ 1]) + witness[offset + 1:]

    line_bytes = artifact.get("pairing_line_packet_bytes", 0)
    line_push = len(push(bytes(line_bytes))) if line_bytes else 0
    trace_bytes = artifact["slope_packet_bytes"]
    slope_start = line_push + len(push(bytes(trace_bytes))) - trace_bytes
    msm_end = slope_start + artifact["msm_slope_count"] * 48
    msm = witness[slope_start:msm_end]
    used = next(i for i, byte in enumerate(msm) if byte)
    public_start = len(witness) - len(push(packet))
    controls = {
        "crossed_statement_with_valid_msm": (witness[:slope_start] + other[slope_start:msm_end]
                                             + witness[msm_end:public_start] + push(other_packet)),
        "tampered_msm_slope": flip(slope_start + used),
        "tampered_b_slope": flip(msm_end),
    }
    if line_bytes:
        controls["tampered_fixed_delta"] = flip(line_push - line_bytes)
        controls["tampered_fixed_gamma"] = flip(line_push - line_bytes + 4 * 48)
    return controls


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--archive", type=Path, required=True, help="prepared CCTP reference")
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--script-era", choices=("genesis", "chronicle"), default="genesis",
                     help="Script era for the native 4thGraph builds")
    args = cli.parse_args()
    engine = chain_metadata()
    if engine["commit"] != CONTEXT_PIN:
        raise ValueError("use the Chronicle-aware chain-gang pin")
    node = Node(os.environ["REGTEST_URL"], os.environ["REGTEST_COOKIE"])
    if node.call("getblockcount", []) or node.call("getconnectioncount", []):
        raise ValueError("the comparison requires a fresh peerless regtest")
    activation = int(os.environ["SCRIPT_LAB_CHRONICLE_HEIGHT"])
    key, proofs, paths = load_cases(args.archive)

    native = native_profiles(key, proofs, script_era=args.script_era)
    locks = {name: bytes.fromhex(profile["artifact"]["script_hex"]) for name, profile in native.items()}
    witnesses = {(name, int(i)): bytes.fromhex(witness) for name, profile in native.items()
                 for i, witness in profile["witness"].items()}
    packets = {(name, int(i)): bytes.fromhex(packet) for name, profile in native.items()
               for i, packet in profile["packets"].items()}
    configured = FORTH_SOURCE.read_text()
    window_word = "2 bind-windowed-public-inputs swap"
    if configured.count(window_word) != 1:
        raise ValueError("use an unchanged prepared CCTP reference source")
    cctp_modes = {
        "cctp-compact": ("bind-public-inputs swap", CCTP_COMPACT_SHA256),
        "cctp-windowed": ("2 bind-windowed-public-inputs-fp2 swap", CCTP_WINDOWED_SHA256),
    }
    for name, (word, digest) in cctp_modes.items():
        lock, _, _ = compile_verifier(args.archive / "4thgraph-source", key, configured.replace(window_word, word))
        if sha256(lock).hexdigest() != digest:
            raise ValueError(f"{name} bytecode does not match the pinned baseline")
        locks[name] = lock
        for i, (signals, proof) in enumerate(proofs):
            witnesses[name, i] = build_unlock(key, signals, proof)

    # Include the profile used for the fixed-key comparison and the upstream
    # affine profile with the precomputed gradients in the lock.
    upstream = {
        "nchain-affine": ZkScript(key, modulo_threshold=1600, gradients_in_witness=True),
        "nchain-affine-lock-gradients": ZkScript(key),
    }
    for name, profile in upstream.items():
        locks[name] = profile.lock("zkscript-affine")
        for i, (signals, proof) in enumerate(proofs):
            witnesses[name, i] = profile.unlock("zkscript-affine", signals, proof)
    print("Built all verifier profiles with the CCTP key.", flush=True)

    replay = Replay(node, activation)
    roots = replay.deploy({case: (Output(100_000, locks[case[0]]),) for case in witnesses})
    spends, rejects = {}, {}
    for (name, i), root in roots.items():
        witness = witnesses[name, i]
        output = public_state(packets[name, i]) if name == "4thgraph-bound" else Output(TERMINAL_VALUE, asm("OP_1"))
        unsigned = Transaction((Input(root.txid_wire(), 0),), (output,))
        if name == "4thgraph-bound":
            tx = unsigned.with_script(0, witness + push(preimage_all(unsigned, 0, 100_000)))
            bad = Transaction(unsigned.inputs, (public_state(packets[name, 1 - i]),))
            bad = bad.with_script(0, witness + push(preimage_all(bad, 0, 100_000)))
            rejects[f"{name}_{i + 1}_wrong_successor"] = replay.reject(name, bad, (root,), [False])
        else:
            tx = unsigned.with_script(0, witness)
        spends[name, i] = tx, (root,)

        if name in ("4thgraph-dynamic", "4thgraph-dynamic-baseline"):
            prefix = witness[:-len(push(packets[name, i]))]
            bad_witness = prefix + push(packets[name, 1 - i])
            other = witnesses[name, 1 - i][:-len(push(packets[name, 1 - i]))]
            claim_bytes = native[name]["artifact"]["vk_claim_bytes"]
            substituted = prefix[:-claim_bytes] + other[-claim_bytes:] + push(packets[name, 1 - i])
            rejects[f"{name}_{i + 1}_crossed_proof_with_valid_msm"] = replay.reject(
                name, tx.with_script(0, substituted), (root,), [False],
            )
        elif name.startswith("4thgraph-affine-"):
            packet, other_packet = packets[name, i], packets[name, 1 - i]
            bad_witness = witness[:-len(push(packet))] + push(other_packet)
            controls = affine_controls(native[name]["artifact"], witness, witnesses[name, 1 - i], packet, other_packet)
            for control, malformed in controls.items():
                rejects[f"{name}_{i + 1}_{control}"] = replay.reject(
                    name, tx.with_script(0, malformed), (root,), [False],
                )
        elif name in cctp_modes:
            suffix, other = (b"".join(map(number, proofs[j][0])) for j in (i, 1 - i))
            if not witness.endswith(suffix):
                raise ValueError("CCTP witness does not end in the public signals")
            bad_witness = witness[:-len(suffix)] + other
        elif name in upstream:
            bad_witness = upstream[name].unlock("zkscript-affine", proofs[1 - i][0], proofs[i][1])
        else:
            continue
        rejects[f"{name}_{i + 1}_crossed_statement"] = replay.reject(
            name, tx.with_script(0, bad_witness), (root,), [False],
        )

    timings = replay.measure(spends)
    for tx, _ in spends.values():
        replay.submit(tx)
    settlement = replay.mine(tx for tx, _ in spends.values())
    rows = {}
    for (name, i), (tx, (parent,)) in spends.items():
        deploy_bytes, spend_bytes = len(parent.serialize()), len(tx.serialize())
        rows[f"{name}_{i + 1}"] = {
            "script_sha256": sha256(locks[name]).hexdigest(), "lock_bytes": len(locks[name]),
            "witness_bytes": len(witnesses[name, i]), "script_sig_bytes": len(tx.inputs[0].script),
            "deployment_bytes": deploy_bytes, "spend_bytes": spend_bytes,
            "total_bytes": deploy_bytes + spend_bytes, "largest_transaction_bytes": max(deploy_bytes, spend_bytes),
            "stack_payload": stack_peaks(tx, (parent,)), "deploy_txid": parent.txid(), "spend_txid": tx.txid(),
            "height": replay.heights[tx.txid()], **timings[name, i],
        }
    result = {
        "node_version": node.version, "profile": os.environ["SCRIPT_LAB_REGTEST_PROFILE"], "chain_gang": engine,
        "samples_per_engine": SAMPLES, "activation_height": activation, "settlement_block": settlement,
        "fixture_sha256": [sha256(path.read_bytes()).hexdigest() for path in paths],
        "4thgraph_profiles": {name: {key: value for key, value in row["artifact"].items() if key != "script_hex"}
                             for name, row in native.items()},
        "public_signals": [list(map(str, signals)) for signals, _ in proofs], "nchain_revision": next(iter(upstream.values())).revisions,
        "nchain_profiles": {name: {"modulo_threshold": model.modulo_threshold,
                                   "gradients_in_witness": model.gradients_in_witness,
                                   "max_multiplier": str(model.max_multipliers[0])} for name, model in upstream.items()},
        "cases": rows, "rejections": rejects,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Mined {len(rows)} spends and rejected {len(rejects)} controls.")


if __name__ == "__main__":
    main()

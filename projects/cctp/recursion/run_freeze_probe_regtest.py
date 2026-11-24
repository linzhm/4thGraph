"""Issue and freeze a disposable token using the isolated freeze proof circuit."""
import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from time import perf_counter

from bsb22 import verifier_fields
from committed_verifier import load_artifact, load_verifying_key
import freeze_probe
from public_inputs import verification_key_point
from run_recursive_mimo import Regtest
from shared.transaction import Input, Output, Transaction
from shared.script import asm
from snarkjs_adapter import load_artifacts, point
from statement import AssetDescriptor
from transaction_relation import TokenState
from usdc_amount import USDC_DECIMALS
from verifier import VerificationKey, unlocking_fields, unlocking_script


def read_key(data, profile):
    if profile == "bsb22":
        return load_verifying_key(data)
    if profile != "plain" or data["nPublic"] != 2 or len(data["IC"]) != 3:
        raise ValueError("expected a supported two-input freeze verifier profile")
    return VerificationKey(
        point(data["vk_alpha_1"]), point(data["vk_beta_2"], twist=True),
        point(data["vk_gamma_2"], twist=True), point(data["vk_delta_2"], twist=True),
        tuple(point(value, allow_infinity=True) for value in data["IC"]),
    ), None


def prove_candidate(binary, directory, output, tx, previous, manifest, key):
    statement = freeze_probe.statement(tx, previous)
    start = perf_counter()
    subprocess.run([str(binary.resolve()), "-mode", "prove", "-dir", str(directory),
                    "-statement", statement.hex(), "-out", str(output)], check=True)
    elapsed = perf_counter() - start
    data = json.loads(output.read_text())
    if (data["statement"] != statement.hex() or
            data["verifying_key_sha256"] != manifest["verifying_key_sha256"]):
        raise ValueError("the native proof does not match the frozen transaction or parameters")
    if manifest["profile"] == "bsb22":
        vk, relation, signals, proof = load_artifact(data)
        fields = verifier_fields(vk, relation, signals, proof)
    else:
        vk, signals, proof = load_artifacts(data, data, data["public_signals"])
        point_coordinates = verification_key_point(vk.ic, signals) or (0, 0)
        fields = (*point_coordinates, *unlocking_fields(vk, signals, proof, projective_g1=True, projective_g2=True))
    if vk != key or signals != freeze_probe.signals(tx, previous):
        raise ValueError("the native proof does not verify the expected freeze public inputs")
    return unlocking_script(fields), {
        "prove_process_seconds": elapsed, "proof_artifact_sha256": sha256(output.read_bytes()).hexdigest(),
        "public_inputs": list(map(str, signals)), "statement_digest": data["statement_digest"],
        "native_prove_seconds": data["prove_seconds"], "native_verify_seconds": data["native_verify_seconds"],
    }


def run(node, binary, parameters, output):
    if node.node.call("getconnectioncount") != 0:
        raise ValueError("use an isolated BSV regtest")
    from test_operational_token import fixture_signer

    _, issuer_sign = fixture_signer(12)
    manifest = json.loads((parameters / "manifest.json").read_text())
    if manifest["test_only"] is not True:
        raise ValueError("the isolated fixture requires test parameters")
    key, relation = read_key(json.loads((parameters / "key.json").read_text()), manifest["profile"])
    setup = node.setup(outputs=1)
    anchor = Input(setup.txid_wire(), 0)
    asset = AssetDescriptor(1, anchor.outpoint(), USDC_DECIMALS, 7, b"r" * 32, b"p" * 32)
    initial = TokenState(asset.asset_id(), 640, node.owner_key)
    lock = freeze_probe.lock(initial, node.freeze_key, key, relation)
    sponsor = Output(max(1_000_000, 2 * len(lock)), asm("OP_1"))
    issued = node.include("test-origin", Transaction((anchor,), (Output(1000, lock), sponsor, sponsor)), (setup,))
    stages = {}
    parent = issued
    for fee_vout, label in enumerate(("freeze", "unfreeze"), 1):
        previous = parent.outputs[0]
        tx = Transaction((Input(parent.txid_wire(), 0), Input(issued.txid_wire(), fee_vout)),
                         (freeze_probe.paired_successor(previous),))
        proof, evidence = prove_candidate(binary, parameters, output / f"{label}-proof.json", tx, previous, manifest, key)
        if label == "freeze":
            # A correctly re-authorized spend with a changed paired value has
            # different public inputs and cannot use the proof for the exact pair.
            changed = replace(tx, outputs=(replace(tx.outputs[0], value=tx.outputs[0].value - 1),))
            changed = changed.with_script(0, proof + freeze_probe.transaction_witness(changed, previous, issuer_sign))
            evidence["changed_pair_value"] = {"txid": changed.txid(), "rejection": node.reject(changed)}
        final = tx.with_script(0, proof + freeze_probe.transaction_witness(tx, previous, issuer_sign))
        parent = node.include(label, final, (parent, issued))
        evidence.update(
            witness_bytes=len(final.inputs[0].script), proof_witness_bytes=len(proof), fee_satoshis=sponsor.value,
            node_timings=node.confirmation_timings[label],
        )
        stages[label] = evidence
    actual = node.node.call("gettxout", parent.txid(), 0, False)
    if parent.outputs[0] != issued.outputs[0] or actual is None or actual["scriptPubKey"]["hex"] != lock.hex():
        raise AssertionError("unfreeze did not restore the exact active token output")
    return {
        "scope": "Isolated issuer-only freeze probe on Bitcoin SV regtest with test-only parameters",
        "asset_id": asset.asset_id().hex(), "lock_bytes": len(lock), "parameters": manifest, "proofs": stages,
        **node.evidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--parameters", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir()
    result = run(Regtest(args.node_url, args.cookie), args.prover, args.parameters, args.out)
    with (args.out / "summary.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()

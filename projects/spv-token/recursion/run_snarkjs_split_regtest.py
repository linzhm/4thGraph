"""Exercise standard .zkey/.wtns on the funded CCTP split commitment fixture."""

import argparse
from dataclasses import replace
import json
from pathlib import Path
from time import perf_counter

from ecdsa import SECP256k1, SigningKey

from circom_witness import calculate_witness
from metal_ntt import MetalNtt
from python_prover import ZKey, prove, write_witness
from regtest_mint import authorization
from regtest_support import Regtest
from shared.script import push
from shared.transaction import Input, Output, Transaction, preimage_all
from snarkjs_adapter import load_artifacts, load_verification_key
from statement import AssetDescriptor, Slot, TRANSFER_DOMAIN, public_inputs
from transaction_relation import TokenState, bind_transfer, token_lock
from transaction_verifier import verifier_key_id, verifier_lock, verifier_witness
from transfer import COMPACT_SCRIPTCODE


def run(node, zkey, wasm, shader, out):
    if node.node.call("getconnectioncount"):
        raise ValueError("use an isolated regtest node")
    with zkey.open("rb") as source:
        key = load_verification_key(ZKey.read(source).verification_key())
    funds = node.setup(outputs=3)
    anchor = Input(funds.txid_wire(), 2)
    asset = AssetDescriptor(1, anchor.outpoint(), 6, 7, b"r" * 32, b"p" * 32)
    lock = verifier_lock(asset, key)
    verifier = node.include("standard-verifier", Transaction(
        (Input(funds.txid_wire(), 0),), (Output(1_000_000, lock),)), (funds,))
    owner = SigningKey.from_secret_exponent(11, curve=SECP256k1)  # Isolated test fixture.
    state = TokenState(asset.asset_id(), 1024, owner.verifying_key.to_string("compressed"))
    parent = node.include("standard-token", Transaction(
        (anchor,), (Output(1_000, token_lock(state, lock)),)), (funds,))
    draft = Transaction((Input(verifier.txid_wire(), 0), Input(parent.txid_wire(), 0)), tuple(
        Output(500, token_lock(replace(state, quantity=amount), lock)) for amount in (640, 384)))
    inputs, outputs = (Slot(1, 1024),), (Slot(0, 640), Slot(1, 384))
    binding = bind_transfer(asset, verifier_key_id(key), draft, (verifier.serialize(), parent.serialize()),
                            lock, inputs, outputs,
                            authenticated_preimage=preimage_all(draft, 0, verifier.outputs[0].value, COMPACT_SCRIPTCODE))
    public = public_inputs(binding.statement)
    body = binding.statement[len(TRANSFER_DOMAIN):]
    request = {"prefix": list(body[:64]), "preimage": list(binding.preimage),
               "inputSlots": [list(body[98:110])], "outputSlots": [list(body[112:124]), list(body[124:136])],
               "digestHigh": public[0], "digestLow": public[1]}

    started = perf_counter()
    witness = calculate_witness(wasm, request)
    witness_file = out / "split.wtns"
    write_witness(witness_file, witness)
    witness_seconds = perf_counter() - started
    artifact = prove(zkey, witness_file, MetalNtt(shader))
    vk, signals, proof = load_artifacts(artifact["key"], artifact["proof"], artifact["public_signals"])
    if vk != key or signals != public:
        raise ValueError("standard proof belongs to a different transaction or verifier")
    script = verifier_witness(asset, key, proof, draft, verifier, inputs, outputs)
    token_preimage = preimage_all(draft, 1, parent.outputs[0].value, parent.outputs[0].script)
    holder = push(authorization(owner, token_preimage)) + push(verifier.serialize())
    holder += push(binding.prevouts) + push(token_preimage)
    payment = draft.with_script(0, script).with_script(1, holder)
    rejection = node.reject(replace(payment, outputs=payment.outputs[::-1]))
    node.include("standard-split", payment, (verifier, parent))
    (out / "proof.json").write_text(json.dumps(artifact, indent=2) + "\n")
    report = {**node.evidence, "scope": "funded CCTP split commitment", "public_signals": artifact["public_signals"],
              "witness_seconds": witness_seconds, "proving": artifact["timings"], "witness_wires": len(witness),
              "reordered_outputs_rejection": rejection, "verification": node.confirmation_timings["standard-split"]}
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("zkey", "wasm", "ntt-shader", "out", "cookie"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--node-url", required=True)
    args = parser.parse_args()
    args.out.mkdir()
    run(Regtest(args.node_url, args.cookie), args.zkey, args.wasm, args.ntt_shader, args.out)


if __name__ == "__main__":
    main()

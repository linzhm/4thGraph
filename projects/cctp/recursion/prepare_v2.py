"""Prepare 1→2 TransferCommitment leaf material for the v2 portable setup."""

import argparse
from importlib.util import find_spec
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from circom_fixture_prover import export_artifacts
from mimo_verifier import MimoProfile
from operational_token import TokenPolicy, ordinary_witness
from shared.transaction import Input, Output, Transaction, hash256
from statement import AssetDescriptor, Slot, transfer_bytes
from test_mimo_verifier import TransferProver
from test_operational_token import fixture_signer
from transaction_relation import TokenState
from transaction_verifier import verifier_key_id
from transfer import COMPACT_SCRIPTCODE


def prepare_v2(build):
    owner, signer = fixture_signer(11)
    admin, _ = fixture_signer(12)
    asset = AssetDescriptor(1, bytes(range(36)), 6, 7, b"r" * 32, b"p" * 32)
    profile = MimoProfile(1, 2, 2, admin)
    prover = TransferProver(build / "transfer", profile)
    key = prover.key
    lock = profile.lock(asset, key)
    policy = TokenPolicy((lock, b"temporary setup seed, never used for verification"), admin)
    has_engine = find_spec("tx_engine") is not None

    def token(quantity):
        return Output(1000, policy.lock(TokenState(asset.asset_id(), quantity, owner)))

    def funding(label):
        return Transaction((Input(hash256(label), 0),), (Output(1_000_000, lock),))

    parents, records = [], []
    for i, quantities in enumerate(((640, 384), (700, 324))):
        verifier = funding(f"v2 leaf verifier {i}".encode())
        origin = Transaction((Input(hash256(f"v2 synthetic origin {i}".encode()), 0),), (token(1024),))
        unsigned = Transaction((Input(verifier.txid_wire(), 0), Input(origin.txid_wire(), 0)),
                               tuple(token(q) for q in quantities))
        inputs = (Slot(1, 1024),)
        outputs = tuple(Slot(j, q) for j, q in enumerate(quantities))
        statement = transfer_bytes(asset, verifier_key_id(key), unsigned, verifier, lock, inputs, outputs,
                                   script_code=COMPACT_SCRIPTCODE)
        signals, proof = prover.prove(asset, unsigned, verifier, inputs, outputs)
        leaf_vk, proof_json, public = export_artifacts(key, signals, proof)
        unlock = profile.witness(asset, key, proof, unsigned, (verifier, origin), policy)
        owner_unlock = ordinary_witness(unsigned, 1, origin, policy, verifier, signer)
        signed = unsigned.with_script(0, unlock).with_script(1, owner_unlock)
        if has_engine:
            from shared.chain_gang import validate_at_heights

            validate_at_heights(signed, (verifier, origin), spend_height=100,
                                activation_height=2, utxo_heights=(3, 3))
        parents.append(signed)
        records.append({"proof": proof_json, "signals": public, "statement": statement.hex(), "txid": signed.txid()})

    verifier = funding(b"v2 child setup seed")
    child = Transaction((Input(verifier.txid_wire(), 0), Input(parents[0].txid_wire(), 0),
                         Input(parents[1].txid_wire(), 1)), (token(700), token(264)))
    statement = transfer_bytes(asset, verifier_key_id(key), child, verifier, lock,
                               (Slot(1, 640), Slot(2, 324)), (Slot(0, 700), Slot(1, 264)),
                               script_code=COMPACT_SCRIPTCODE)
    return {"inner_vk": leaf_vk, "parents": records, "context": hash256(statement).hex(),
            "context_statement": statement.hex(), "chain_gang_validated": has_engine,
            "inner_constraints": len(prover.prover.rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="cctp-v2-recursion-") as tmp:
        data = prepare_v2(Path(tmp))
    args.output.write_text(json.dumps(data, indent=2) + "\n")


if __name__ == "__main__":
    main()

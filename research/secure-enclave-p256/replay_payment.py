"""Replay the public ordinary-payment vector offline. No signing key is required."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from tx_engine import Tx

from checked_wallet import sign_payment
from universal import authorization


VECTOR_DIR = Path(__file__).resolve().parents[2] / "docs/research/p2pkh-r1/spend-all"


def replay():
    vector = json.loads((VECTOR_DIR / "vector.json").read_text())
    parent = Tx.parse(bytes.fromhex((VECTOR_DIR / vector["parent_tx_file"]).read_text()))
    unsigned = Tx.parse(bytes.fromhex(vector["unsigned_tx_hex"]))
    if parent.id() != vector["parent_txid"] or unsigned.tx_ins[0].prev_tx != parent.id():
        raise ValueError("fixture parent outpoint mismatch")
    auth = authorization(unsigned, vector["input_index"], parent.tx_outs[vector["vout"]].amount,
                         int(vector["requested_type"], 16))
    if auth.preimage.hex() != vector["preimage_hex"]:
        raise ValueError("fixture preimage mismatch")

    def recorded_signature(digest):
        if digest.hex() != vector["digest_hex"]:
            raise ValueError("recorded signature belongs to a different digest")
        return bytes.fromhex(vector["signature_raw_hex"])

    with TemporaryDirectory() as directory:
        signed = sign_payment(
            parent, vector["vout"], unsigned.tx_outs, vector["fee_sats"],
            bytes.fromhex(vector["public_key_x963"]), recorded_signature,
            Path(directory) / "fixture-history.sqlite",
        )
    expected = bytes.fromhex((VECTOR_DIR / vector["signed_tx_file"]).read_text())
    if signed.serialize() != expected or signed.id() != vector["signed_txid"]:
        raise ValueError("signed transaction differs from the published bytes")
    return parent, signed


if __name__ == "__main__":
    _, transaction = replay()
    print(f"{transaction.id()}  ({len(transaction.serialize())} bytes)")

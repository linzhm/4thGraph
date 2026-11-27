"""Offline BSV script examples. Fixture keys are public; never fund them."""
import json

from tx_engine import Script, Tx, TxIn, TxOut, Wallet, hash160

from fourthgraph.bsv.native_payments import p2pk_lock, p2pkh_lock
from fourthgraph.bsv.transaction import blob

OWNER = Wallet.from_int("BSV_Testnet", 1)
OTHER = Wallet.from_int("BSV_Testnet", 2)
OWNER_PUB = bytes.fromhex(OWNER.get_public_key_as_hexstr())
OTHER_PUB = bytes.fromhex(OTHER.get_public_key_as_hexstr())

TEMPLATES = {
    "p2pkh": (
        f"OP_DUP OP_HASH160 0x{bytes(hash160(OWNER_PUB)).hex()} OP_EQUALVERIFY OP_CHECKSIG",
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    ),
    "p2pk": (
        f"0x{OWNER_PUB.hex()} OP_CHECKSIG",
        "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
    ),
}
COMPILED_LOCKS = {
    "p2pk": p2pk_lock(OWNER_PUB),
    "p2pkh": p2pkh_lock(bytes(hash160(OWNER_PUB))),
}


def fixture(template, lock, signer, presented_key):
    # Synthetic parent references an invented outpoint. It is not broadcastable.
    parent = Tx(1, [TxIn("11" * 32, 0, Script())], [TxOut(10_000, lock)])
    outputs = [TxOut(9_000, OWNER.get_locking_script())]
    unsigned = Tx(1, [TxIn(parent.id(), 0, Script())], outputs)
    # Wallet's helper emits the signature and pubkey; P2PK only pushes the signature.
    signed = signer.sign_tx(0, parent, unsigned)
    raw = bytes(signed.tx_ins[0].script_sig.raw_serialize())
    signature = raw[1 : 1 + raw[0]]
    if not (9 <= len(signature) <= 73 and signature[0] == 0x30 and signature[-1] == 0x41):
        raise ValueError("unexpected signature encoding from wallet helper")
    asm = f"0x{signature.hex()}"
    if template == "p2pkh":
        asm += f" 0x{presented_key.hex()}"
    unlock = Script.parse_string(asm)
    return parent, Tx(1, [TxIn(parent.id(), 0, unlock)], outputs), unlock, asm


def main():
    cases = []
    for name, (lock_asm, expected_hex) in TEMPLATES.items():
        lock = Script.parse(blob(COMPILED_LOCKS[name]))
        lock_hex = bytes(lock.raw_serialize()).hex()
        if lock_hex != expected_hex:
            raise AssertionError(f"{name}: unexpected locking script hex {lock_hex}")
        variants = [("valid", OWNER, OWNER_PUB), ("wrong_signature", OTHER, OWNER_PUB)]
        if name == "p2pkh":
            variants.append(("wrong_pubkey_hash", OTHER, OTHER_PUB))
        for case, signer, pubkey in variants:
            parent, spend, unlock, unlock_asm = fixture(name, lock, signer, pubkey)
            error = None
            try:
                spend.validate([parent])
            except (ValueError, RuntimeError) as exc:
                error = str(exc)
            expected_error = {
                "valid": None,
                "wrong_signature": "OP_CHECKSIG NULLFAIL",
                "wrong_pubkey_hash": "OP_EQUALVERIFY operands are not equal",
            }[case]
            if (error is None if expected_error is None else
                    error == f"Error evaluating the script `{expected_error}`") is False:
                raise AssertionError(f"{name}/{case}: unexpected validation result {error!r}")
            cases.append(
                dict(template=name, case=case, accepted=error is None, error=error,
                     lock_asm=lock_asm, lock_hex=lock_hex,
                     unlock_asm=unlock_asm, unlock_hex=bytes(unlock.raw_serialize()).hex(),
                     parent_tx_hex=parent.as_hexstr(), spend_tx_hex=spend.as_hexstr())
            )
    print(json.dumps(cases, indent=2))


if __name__ == "__main__":
    main()

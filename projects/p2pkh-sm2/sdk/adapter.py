"""P2PKH-SM2 lock recognition and external raw or SignedData authorization."""
from p2pkh_sm2 import identify, locking_script_from_owner_hash, locking_script_from_public_key
from p2pkh_sm2 import public_key_hash160, sign_input
from signed_data import signed_data_signer

lock_owner = locking_script_from_owner_hash


def lock(public_key, profile):
    if profile not in (None, "v1.0.0"):
        raise ValueError("unsupported SM2 template profile")
    return locking_script_from_public_key(public_key)


def recognize(script, public_key):
    result = identify(script)
    if result is None:
        return None
    _, owner = result
    if public_key is not None and owner != public_key_hash160(public_key):
        return None
    return {"template": "v1.0.0", "ownerHash160": owner.hex()}


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    if "signerIdentifier" in options:
        signer = signed_data_signer(signer, public_key, signer_identifier=options["signerIdentifier"])
    return sign_input(tx, index, funding_raw, public_key, signer, sighash,
                      chronicle_active=options.get("chronicleActive", False))

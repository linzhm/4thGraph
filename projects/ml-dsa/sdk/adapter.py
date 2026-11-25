"""Pure ML-DSA-44 payment authorization for an external empty-context signer."""
from payment import sign_spend as authorize
from script import locking_script


def lock(public_key, profile):
    if profile not in (None, "pure-ml-dsa-44"):
        raise ValueError("unsupported ML-DSA payment profile")
    return locking_script(public_key)


def recognize(script, public_key):
    if public_key is None:
        raise ValueError("ML-DSA recognition requires the expected public key")
    return {"template": "pure-ml-dsa-44"} if script == locking_script(public_key) else None


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    return authorize(tx, index, funding_raw, public_key, signer, sighash=sighash)

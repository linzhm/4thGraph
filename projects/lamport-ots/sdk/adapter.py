"""Authenticate the transaction-bound Lamport lock and use an external signer."""
from payment import sign_spend as authorize
from script import committed_locking_script, legacy_locking_script, locking_script

TEMPLATES = {"full-key": locking_script, "committed-key": committed_locking_script, "legacy": legacy_locking_script}


def lock(public_key, profile):
    profile = "full-key" if profile is None else profile
    if profile not in ("full-key", "committed-key"):
        raise ValueError("expected full-key or committed-key")
    return TEMPLATES[profile](public_key)


def recognize(script, public_key):
    if public_key is None:
        raise ValueError("Lamport recognition requires the expected public key")
    for name, create in TEMPLATES.items():
        if script == create(public_key):
            return {"template": name}
    return None


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    return authorize(tx, index, funding_raw, public_key, signer, sighash=sighash)

"""Authenticate the transaction-bound Lamport lock and use an external signer."""
from payment import sign_previous as authorize_previous
from payment import sign_spend as authorize
from script import (
    committed_locking_script, compact_forth_committed_locking_script, forth_committed_locking_script,
    legacy_locking_script, locking_script, v020_forth_committed_locking_script,
)

RECEIVE_TEMPLATES = {
    "full-key": locking_script,
    "committed-key": committed_locking_script,
    "committed-key-forth": forth_committed_locking_script,
    "committed-key-forth-compact": compact_forth_committed_locking_script,
    "committed-key-forth-v0.2.0": v020_forth_committed_locking_script,
}


def lock(public_key, profile):
    profile = "full-key" if profile is None else profile
    if profile not in tuple(RECEIVE_TEMPLATES):
        raise ValueError(f"expected one of {', '.join(RECEIVE_TEMPLATES)}")
    return RECEIVE_TEMPLATES[profile](public_key)


def recognize(script, public_key):
    if public_key is None:
        raise ValueError("Lamport recognition requires the expected public key")
    for name, create in (*RECEIVE_TEMPLATES.items(), ("legacy", legacy_locking_script)):
        if script == create(public_key):
            return {"template": name}
    return None


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    return authorize(tx, index, funding_raw, public_key, signer, sighash=sighash,
                     compress_otda=options.get("compressOtda", False))


def sign_previous(tx, index, previous, public_key, signer, sighash, options):
    return authorize_previous(tx, index, previous, public_key, signer, sighash=sighash,
                              compress_otda=options.get("compressOtda", False))

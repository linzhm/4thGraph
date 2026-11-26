"""Connect the unified wallet SDK to the fixed Schnorr payment template."""

from bip340 import lift_x
from payment import lock_for_public_key, sign_previous as authorize_previous, sign_spend as authorize
from schnorr_script import lock_for_owner, owner_hash, recognize_template


def lock_owner(owner, profile=None):
    return lock_for_owner(owner, version=profile)


def lock(public_key, profile):
    return lock_for_public_key(public_key, version=profile)


def recognize(script, public_key):
    match = recognize_template(script)
    if match is None:
        return None
    version, owner = match
    if public_key is not None and (lift_x(public_key) is None or owner_hash(public_key) != owner):
        return None
    return {"template": version, "ownerHash160": owner.hex()}


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    return authorize(tx, index, funding_raw, public_key, signer, sighash=sighash,
                     chronicle_active=options.get("chronicleActive", False), compress_otda=options.get("compressOtda"))


def sign_previous(tx, index, previous, public_key, signer, sighash, options):
    return authorize_previous(tx, index, previous, public_key, signer, sighash=sighash,
                              chronicle_active=options.get("chronicleActive", False), compress_otda=options.get("compressOtda"))

"""Connect the unified wallet SDK to the fixed Schnorr payment template."""

from bip340 import lift_x
from payment import lock_for_public_key, sign_previous as authorize_previous, sign_spend as authorize
from schnorr_script import TEMPLATE_VERSION, lock_for_owner, owner_hash, recognize as recognize_owner


def _check_profile(profile):
    if profile not in (None, TEMPLATE_VERSION):
        raise ValueError("unsupported Schnorr locking template")


def lock_owner(owner, profile=None):
    _check_profile(profile)
    return lock_for_owner(owner)


def lock(public_key, profile):
    _check_profile(profile)
    return lock_for_public_key(public_key)


def recognize(script, public_key):
    owner = recognize_owner(script)
    if owner is None:
        return None
    if public_key is not None and (lift_x(public_key) is None or owner_hash(public_key) != owner):
        return None
    return {"template": TEMPLATE_VERSION, "ownerHash160": owner.hex()}


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    return authorize(tx, index, funding_raw, public_key, signer, sighash=sighash,
                     chronicle_active=options.get("chronicleActive", False))


def sign_previous(tx, index, previous, public_key, signer, sighash, options):
    return authorize_previous(tx, index, previous, public_key, signer, sighash=sighash,
                              chronicle_active=options.get("chronicleActive", False))

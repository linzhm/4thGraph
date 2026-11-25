"""WOTS+ payment formats, including the cached-steps OTDA option."""
from payment import sign_previous as authorize_previous
from payment import sign_spend as authorize
from script import locking_script

TEMPLATES = {"canonical": False, "cached-constants": True, "cached-steps": "steps"}


def lock(public_key, profile):
    profile = "canonical" if profile is None else profile
    if profile not in TEMPLATES:
        raise ValueError("unknown WOTS+ template profile")
    return locking_script(public_key, cached_constants=TEMPLATES[profile])


def recognize(script, public_key):
    if public_key is None:
        raise ValueError("WOTS+ recognition requires the expected public key")
    for name, profile in TEMPLATES.items():
        if script == locking_script(public_key, cached_constants=profile):
            return {"template": name}
    return None


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    return authorize(tx, index, funding_raw, public_key, signer, sighash=sighash,
                     compress_otda=options.get("compressOtda", False))


def sign_previous(tx, index, previous, public_key, signer, sighash, options):
    return authorize_previous(tx, index, previous, public_key, signer, sighash=sighash,
                     compress_otda=options.get("compressOtda", False))

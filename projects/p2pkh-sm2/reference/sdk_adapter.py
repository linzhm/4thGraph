"""P2PKH-SM2 lock recognition and external raw or SignedData authorization."""
from assemble import TEMPLATE_PROFILES, TEMPLATE_VERSION
from p2pkh_sm2 import identify, locking_script_from_owner_hash, locking_script_from_public_key
from p2pkh_sm2 import public_key_hash160, sign_input, sign_previous as authorize_previous
from signed_data import signed_data_signer


VERSIONS = {profile: version for version, profile in TEMPLATE_PROFILES.items()}


def template_version(profile):
    if profile is None:
        return TEMPLATE_VERSION
    if not isinstance(profile, str) or profile not in VERSIONS:
        raise ValueError("unsupported SM2 template profile")
    return VERSIONS[profile]


def lock_owner(owner, profile=None):
    return locking_script_from_owner_hash(owner, version=template_version(profile))


def lock(public_key, profile):
    return locking_script_from_public_key(public_key, version=template_version(profile))


def recognize(script, public_key):
    result = identify(script)
    if result is None:
        return None
    version, owner = result
    if public_key is not None and owner != public_key_hash160(public_key):
        return None
    return {"template": TEMPLATE_PROFILES[version], "ownerHash160": owner.hex()}


def sign_spend(tx, index, funding_raw, public_key, signer, sighash, options):
    if "signerIdentifier" in options:
        signer = signed_data_signer(signer, public_key, signer_identifier=options["signerIdentifier"])
    return sign_input(tx, index, funding_raw, public_key, signer, sighash,
                      chronicle_active=options.get("chronicleActive", False),
                      compress_otda=options.get("compressOtda"))


def sign_previous(tx, index, previous, public_key, signer, sighash, options):
    if "signerIdentifier" in options:
        signer = signed_data_signer(signer, public_key, signer_identifier=options["signerIdentifier"])
    return authorize_previous(tx, index, previous, public_key, signer, sighash,
                              options.get("chronicleActive", False),
                              compress_otda=options.get("compressOtda"))

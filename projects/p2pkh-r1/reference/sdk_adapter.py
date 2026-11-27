"""Connect the shared wallet API to the P-256 reference implementation."""
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from tx_engine import Tx

import p2pkh_r1
from fixed_templates import OPTIMIZED_TEMPLATE_VERSION, compiled_template
from wallet import previous_output_unlock

OPTIMIZED_PROFILE = f"v{OPTIMIZED_TEMPLATE_VERSION}"
PROFILES = {
    59582: "v0.1.0", 47510: "compiled", 46302: "v0.2.0",
    len(compiled_template(template_version=OPTIMIZED_TEMPLATE_VERSION).script): OPTIMIZED_PROFILE,
}


def lock_owner(owner, profile=None):
    if profile == "compiled":
        return p2pkh_r1.locking_script_from_owner_hash(owner, compiled_curve=True)
    if profile not in (None, "v0.1.0", "v0.2.0", OPTIMIZED_PROFILE):
        raise ValueError("unsupported R1 template")
    return p2pkh_r1.locking_script_from_owner_hash(
        owner, template_version=profile[1:] if profile is not None else None,
    )


def lock(public_key, profile):
    return lock_owner(p2pkh_r1.public_key_hash160(public_key), profile)


def recognize(script, public_key):
    owner = p2pkh_r1.recognize(script)
    if owner is None or (public_key is not None and p2pkh_r1.public_key_hash160(public_key) != owner):
        return None
    return {"template": PROFILES[len(script)], "ownerHash160": owner.hex()}


def sign_previous(tx, index, previous, public_key, signer, sighash, options):
    history = Path(options.get("historyPath", ""))
    if not history.is_absolute():
        raise ValueError("R1 requires an absolute persistent historyPath")
    try:
        unlock = previous_output_unlock(
            Tx.parse(tx.serialize()), index, previous.value, previous.script, sighash,
            public_key, signer, history, compress_otda="paired" if options.get("compressOtda") else False,
            sign_message=options.get("signMessage", False),
        )
    except InvalidSignature as error:
        raise ValueError("invalid P-256 signature") from error
    return tx.with_script(index, bytes(unlock.raw_serialize()))

"""Connect the shared wallet API to Deferred R1 funding and activation."""
from deferred import activate_previous, funding_output, funding_output_from_owner_hash
from deferred import recognize as recognize_output
from shared.transaction import Output


def _target(profile):
    if profile not in (None, "v0.2.0"):
        raise ValueError("new Deferred outputs use v0.2.0")
    return "0.2.0"


def lock(public_key, profile, value):
    return funding_output(value, public_key, target_r1_version=_target(profile)).script


def lock_owner(owner, profile, value):
    return funding_output_from_owner_hash(value, owner, target_r1_version=_target(profile)).script


def recognize(script, public_key, value):
    result = recognize_output(Output(value, script), expected_key=public_key)
    if result is None:
        return None
    recognition = {
        "template": "v0.1.0" if result.public_key is not None else f"v{result.target_r1_version}",
        "ownerHash160": result.owner_hash160.hex(),
        "targetTemplate": f"v{result.target_r1_version}",
        "targetScriptSha256": result.script_hash.hex(),
        "targetTxOutHash256": result.output_hash.hex(),
    }
    if result.public_key is not None:
        recognition["publicKey"] = result.public_key.hex()
    return recognition

"""Connect the shared wallet API to Deferred R1 funding and activation."""
from deferred import (
    ASSEMBLY_TEMPLATE_VERSION, DEFERRED_TEMPLATE_VERSION, RELEASE_BUILD,
    activate_previous, funding_output, funding_output_from_owner_hash,
)
from deferred import recognize as recognize_output
from fourthgraph.bsv.transaction import Output


def _build(profile):
    if profile in (None, f"v{DEFERRED_TEMPLATE_VERSION}"):
        return RELEASE_BUILD
    if profile == f"v{ASSEMBLY_TEMPLATE_VERSION}":
        return None
    raise ValueError(f"unknown Deferred template {profile!r}")


def lock(public_key, profile, value):
    return funding_output(value, public_key, optimization=_build(profile)).script


def lock_owner(owner, profile, value):
    return funding_output_from_owner_hash(value, owner, optimization=_build(profile)).script


def recognize(script, public_key, value):
    result = recognize_output(Output(value, script), expected_key=public_key)
    if result is None:
        return None
    recognition = {
        "template": f"v{result.template_version}" if result.template_version else f"forth-{result.optimization}",
        "ownerHash160": result.owner_hash160.hex(),
        "targetTemplate": f"v{result.target_r1_version}",
        "targetScriptSha256": result.script_hash.hex(),
        "targetTxOutHash256": result.output_hash.hex(),
    }
    if result.public_key is not None:
        recognition["publicKey"] = result.public_key.hex()
    return recognition

"""Public test-only keys for the SDK and offline example."""

from coincurve import PrivateKey

from musig2_fixture import Policy, fixture_keys, fixture_sign
from payment import lock_for_public_key
from schnorr_script import TEMPLATE_VERSION


def cases():
    def sign_with(key):
        return lambda message: key.sign_schnorr(message, aux_randomness=bytes(32))

    for version, scalar, sighash in (
        (TEMPLATE_VERSION, 3, 0x41),
        (TEMPLATE_VERSION, 11, 0x63),
        ("v0.9.0", 3, 0x41),
        ("v0.9.0", 3, 0x63),
        ("v0.8.0", 3, 0x41),
        ("v0.8.0", 3, 0x63),
        ("v0.7.0", 3, 0x41),
        ("v0.7.0", 3, 0x63),
        ("v0.6.0", 3, 0x41),
        ("v0.6.0", 3, 0x63),
    ):
        key = PrivateKey.from_int(scalar)
        yield dict(public_key=key.public_key_xonly.format(), signer=sign_with(key),
                   profile=version, sighash=sighash)

    key = PrivateKey.from_int(3)
    public = key.public_key_xonly.format()
    destination = lock_for_public_key(PrivateKey.from_int(13).public_key_xonly.format())
    for sighash, options in (
        (0x61, {"reconstructed": True}),
        (0xe3, {"compress_otda": True, "reconstructed": True}),
        (0x61, {"compress_otda": False, "reconstructed": False}),
    ):
        yield dict(public_key=public, signer=sign_with(key), profile=TEMPLATE_VERSION,
                   sighash=sighash, destination=destination, **options)

    keys = fixture_keys("wallet-sdk/musig2")
    policy = Policy(tuple(key.public_key.format() for key in keys))
    for sighash in (0x41, 0x63):
        def sign_aggregate(message, mode=sighash):
            return fixture_sign(keys, policy, f"wallet-sdk/musig2/{mode:02x}", message)

        yield dict(public_key=policy.aggregate_x, signer=sign_aggregate,
                   profile=TEMPLATE_VERSION, sighash=sighash)

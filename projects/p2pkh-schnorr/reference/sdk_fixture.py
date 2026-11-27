"""Public test-only keys for the SDK and offline example."""

from coincurve import PrivateKey

from musig2_fixture import Policy, fixture_keys, fixture_sign
from schnorr_script import TEMPLATE_VERSION, lock_for_owner
from fourthgraph.bsv.transaction import Output


def cases():
    def sign_with(key):
        return lambda message: key.sign_schnorr(message, aux_randomness=bytes(32))

    for version, scalar, sighash in (
        (TEMPLATE_VERSION, 3, 0x41),
        (TEMPLATE_VERSION, 11, 0x63),
        ("v0.16.0", 3, 0x41),
        ("v0.16.0", 3, 0x63),
        ("v0.15.0", 3, 0x41),
        ("v0.15.0", 3, 0x63),
        ("v0.14.0", 3, 0x41),
        ("v0.14.0", 3, 0x63),
        ("v0.13.0", 3, 0x41),
        ("v0.13.0", 3, 0x63),
        ("v0.12.0", 3, 0x41),
        ("v0.12.0", 3, 0x63),
        ("v0.11.0", 3, 0x41),
        ("v0.11.0", 3, 0x63),
        ("v0.10.0", 3, 0x41),
        ("v0.10.0", 3, 0x63),
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
    outputs = (Output(4_950, lock_for_owner(bytes(20))),
               Output(4_950, lock_for_owner(bytes(range(20)), version="v0.16.0")))
    case = dict(public_key=key.public_key_xonly.format(), signer=sign_with(key), outputs=outputs,
                profile=TEMPLATE_VERSION, sighash=0x61)
    yield dict(case, reconstructed=True)
    yield dict(case, compress_otda=True, reconstructed=True)
    yield dict(case, compress_otda=False, reconstructed=False)

    keys = fixture_keys("wallet-sdk/musig2")
    policy = Policy(tuple(key.public_key.format() for key in keys))
    for sighash in (0x41, 0x63):
        def sign_aggregate(message, mode=sighash):
            return fixture_sign(keys, policy, f"wallet-sdk/musig2/{mode:02x}", message)

        yield dict(public_key=policy.aggregate_x, signer=sign_aggregate,
                   profile=TEMPLATE_VERSION, sighash=sighash)

"""Public test-only keys for the SDK and offline example."""

from coincurve import PrivateKey

from schnorr_script import TEMPLATE_VERSION


def cases():
    def sign_with(key):
        return lambda message: key.sign_schnorr(message, aux_randomness=bytes(32))

    for scalar, sighash in ((3, 0x41), (11, 0x63)):
        key = PrivateKey.from_int(scalar)
        yield dict(public_key=key.public_key_xonly.format(), signer=sign_with(key),
                   profile=TEMPLATE_VERSION, sighash=sighash)

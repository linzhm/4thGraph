from sm2 import USER_ID, encode_public, fixture_sign, mul
from test_signed_data import ISSUER_AND_SERIAL, signed_data
from test_sm2 import der_signature


def cases():
    for scalar, sighash in ((1, 0x41), (2, 0x61)):
        def signer(message, user_id):
            assert user_id == USER_ID
            return fixture_sign(scalar, message, 19, user_id)

        yield dict(public_key=encode_public(mul(scalar)), signer=signer, profile="v1.0.0",
                   bytes=144925, sighash=sighash)

    def signed_data_provider(message, user_id):
        assert user_id == USER_ID
        return signed_data(der_signature(fixture_sign(3, message, 23, user_id)), attached=message)

    yield dict(public_key=encode_public(mul(3)), signer=signed_data_provider, profile="v1.0.0",
               bytes=144925, sighash=0x61, signer_identifier=ISSUER_AND_SERIAL)

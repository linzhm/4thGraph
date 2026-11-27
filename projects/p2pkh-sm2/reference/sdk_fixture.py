from assemble import COMPILED_POINT_TEMPLATE_VERSION, PACKED_SM3_TEMPLATE_VERSION, SCHEDULED_TEMPLATE_VERSION
from assemble import SIGNED_RESIDUE_TEMPLATE_VERSION, SIGNED_WINDOW_TEMPLATE_VERSION
from assemble import PUBLIC_TABLE_TEMPLATE_VERSION, SPLIT_ROTATION_TEMPLATE_VERSION, TEMPLATE_PROFILES
from assemble import AFFINE_GENERATOR_TEMPLATE_VERSION, CARRIED_FIELD_TEMPLATE_VERSION, WINDOW_DOUBLING_TEMPLATE_VERSION
from fourthgraph.bsv.transaction import Output
from p2pkh_sm2 import MIXED_OTDA_VERSIONS, locking_script_from_public_key
from sm2 import USER_ID, encode_public, fixture_sign, mul


def raw_signer(scalar):
    def signer(message, user_id):
        assert user_id == USER_ID
        return fixture_sign(scalar, message, 19, user_id)

    return signer


def cases():
    for scalar, sighash in ((1, 0x41), (2, 0x61)):
        yield dict(public_key=encode_public(mul(scalar)), signer=raw_signer(scalar), profile="v1.0.0",
                   bytes=144925, sighash=sighash)

    from test_signed_data import ISSUER_AND_SERIAL, signed_data
    from test_sm2 import der_signature

    def signed_data_provider(message, user_id):
        assert user_id == USER_ID
        return signed_data(der_signature(fixture_sign(3, message, 23, user_id)), attached=message)

    yield dict(public_key=encode_public(mul(3)), signer=signed_data_provider, profile="v1.0.0",
               bytes=144925, sighash=0x61, signer_identifier=ISSUER_AND_SERIAL)

    destination = locking_script_from_public_key(encode_public(mul(9)))
    yield dict(public_key=encode_public(mul(2)), signer=raw_signer(2), profile="v1.0.0",
               bytes=144925, sighash=0xe3, destination=destination, reconstructed=True)
    yield dict(public_key=encode_public(mul(3)), signer=signed_data_provider, profile="v1.0.0",
               bytes=144925, sighash=0x61, destination=destination, reconstructed=True,
               signer_identifier=ISSUER_AND_SERIAL)
    yield dict(public_key=encode_public(mul(2)), signer=raw_signer(2), profile="v1.0.0",
               bytes=144925, sighash=0x61, compress_otda=False, destination=destination, reconstructed=False)

    for version, size in (
        (SCHEDULED_TEMPLATE_VERSION, 131565),
        (SIGNED_RESIDUE_TEMPLATE_VERSION, 125616),
        (PACKED_SM3_TEMPLATE_VERSION, 121847),
        (COMPILED_POINT_TEMPLATE_VERSION, 110747),
        (SPLIT_ROTATION_TEMPLATE_VERSION, 100663),
        (SIGNED_WINDOW_TEMPLATE_VERSION, 98362),
        (WINDOW_DOUBLING_TEMPLATE_VERSION, 96616),
        (AFFINE_GENERATOR_TEMPLATE_VERSION, 95790),
        (CARRIED_FIELD_TEMPLATE_VERSION, 94355),
        (PUBLIC_TABLE_TEMPLATE_VERSION, 94117),
    ):
        destination = locking_script_from_public_key(encode_public(mul(9)), version=version)
        profile = TEMPLATE_PROFILES[version]
        yield dict(public_key=encode_public(mul(2)), signer=raw_signer(2), profile=profile,
                   bytes=size, sighash=0x41)
        yield dict(public_key=encode_public(mul(3)), signer=signed_data_provider, profile=profile,
                   bytes=size, sighash=0x61, destination=destination, reconstructed=True,
                   signer_identifier=ISSUER_AND_SERIAL)

    mixed_outputs = tuple(
        Output(4_950, locking_script_from_public_key(encode_public(mul(9)), version=version))
        for version in reversed(MIXED_OTDA_VERSIONS)
    )
    yield dict(public_key=encode_public(mul(2)), signer=raw_signer(2), profile="v1.7.0",
               bytes=98362, sighash=0x61, outputs=mixed_outputs, reconstructed=True)

    latest_outputs = tuple(
        Output(3_300, locking_script_from_public_key(encode_public(mul(scalar)),
                                                    version=PUBLIC_TABLE_TEMPLATE_VERSION))
        for scalar in (9, 10, 11)
    )
    latest_case = dict(public_key=encode_public(mul(2)), signer=raw_signer(2), profile="v1.12.0",
                       bytes=94117, outputs=latest_outputs)
    for flag in (0x61, 0xe1):
        yield dict(latest_case, sighash=flag, reconstructed=True)
    yield dict(latest_case, sighash=0x61, compress_otda=False, reconstructed=False)

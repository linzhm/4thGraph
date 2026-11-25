"""Benchmark fixtures for the publicly released SM2 payment template."""
from functools import partial

from p2pkh_sm2 import locking_script_from_public_key, sign_input
from sm2 import N, encode_public, fixture_sign, mul
from shared.benchmark_cases import Coin, Template, seed
from shared.transaction import Output


def sm2_coin(label, value, *, compress_otda=None):
    scalar = 1 + int.from_bytes(seed(label), "big") % (N - 2)
    key = encode_public(mul(scalar))

    def sign(message, user_id):
        nonce = 1 + int.from_bytes(seed(label + "/" + message.hex()), "big") % (N - 1)
        return fixture_sign(scalar, message, nonce, user_id)

    def unlock(tx, index, parent, flag, _scratch):
        return sign_input(tx, index, parent.serialize(), key, sign, flag, compress_otda=compress_otda)

    return Coin(Output(value, locking_script_from_public_key(key)), unlock)


TEMPLATES = {
    "v1.0.0": Template(partial(sm2_coin, compress_otda=False)),
    "v1.1.0": Template(sm2_coin),
}


def components(samples):
    from pathlib import Path

    from assemble import sm3_blocks
    from shared.benchmark_validation import timed
    from shared.script import assemble
    from signed_data import signed_data_signer
    from sm2 import USER_ID, verify
    from test_signed_data import ISSUER_AND_SERIAL, signed_data, der_signature

    asm_path = Path(__file__).with_name("asm")
    curve_bytes = {entry: len(assemble(asm_path, bytes(20), entry=entry))
                   for entry in ("UNPACK_SM2_INPUTS", "CHECK_SM2_FIELDS", "VERIFY_SM2_POINT")}
    message = bytes(32)
    key = encode_public(mul(1))
    signature = fixture_sign(1, message, 2)
    envelope = signed_data(der_signature(signature), attached=message)
    adapter = signed_data_signer(lambda *_: envelope, key, signer_identifier=ISSUER_AND_SERIAL)
    valid, raw_ms = timed(lambda: verify(key, message, signature), samples)
    adapted, signed_data_ms = timed(lambda: adapter(message, USER_ID), samples)
    if not valid or adapted != signature:
        raise ValueError("SM2 benchmark component verification did not reproduce the raw signature")
    return {"sm3_script_bytes": {name: len(block) for name, block in sm3_blocks().items()},
            "curve_script_bytes": curve_bytes, "signed_data_fixture_bytes": len(envelope),
            "off_chain_raw_verify_median_ms": raw_ms,
            "off_chain_signed_data_verify_and_extract_median_ms": signed_data_ms}

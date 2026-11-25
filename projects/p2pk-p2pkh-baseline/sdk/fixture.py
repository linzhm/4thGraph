from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize


def cases():
    for scalar, profile, length, sighash in ((1, "p2pkh", 25, 0x41), (2, "p2pk", 35, 0x63)):
        key = SigningKey.from_secret_exponent(scalar, curve=SECP256k1)

        def signer(digest):
            return key.sign_digest_deterministic(digest, sigencode=sigencode_der_canonize)

        yield dict(public_key=key.verifying_key.to_string("compressed"), signer=signer,
                   profile=profile, bytes=length, sighash=sighash)

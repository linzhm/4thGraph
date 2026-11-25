import os

from mldsa import test_only_vector


def cases():
    openssl = os.environ.get("ML_DSA_OPENSSL", "openssl")
    for seed, sighash in ((3, 0x41), (4, 0xe1)):
        seed = bytes([seed]) * 32
        public, _ = test_only_vector(seed, bytes(32), openssl=openssl)

        def signer(message):
            derived, signature = test_only_vector(seed, message, openssl=openssl)
            assert public == derived
            return signature

        yield dict(public_key=public, signer=signer, profile="pure-ml-dsa-44", sighash=sighash)

from mldsa import test_only_vector


def cases():
    for seed, sighash in ((3, 0x41), (4, 0xe1)):
        seed = bytes([seed]) * 32
        public, _ = test_only_vector(seed, bytes(32))

        def signer(digest):
            derived, signature = test_only_vector(seed, digest)
            assert public == derived
            return signature

        yield dict(public_key=public, signer=signer, profile="pure-ml-dsa-44", sighash=sighash)

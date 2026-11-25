"""Pure ML-DSA-44 benchmark fixtures with the independent OpenSSL signer."""
import os

from mldsa import test_only_vector
from payment import sign_spend
from script import locking_script
from shared.benchmark_cases import Coin, Template, seed
from shared.transaction import Output


def coin(label, value):
    private_seed = seed(label)
    openssl = os.environ.get("ML_DSA_OPENSSL", "openssl")
    public, _ = test_only_vector(private_seed, bytes(32), openssl=openssl)

    def signer(digest):
        derived, signature = test_only_vector(private_seed, digest, openssl=openssl)
        if derived != public:
            raise ValueError("OpenSSL returned a different fixture key")
        return signature

    def unlock(tx, index, parent, flag, _scratch):
        return sign_spend(tx, index, parent.serialize(), public, signer, sighash=flag)

    return Coin(Output(value, locking_script(public)), unlock)


TEMPLATES = {"pure-ml-dsa-44": Template(coin)}


def components(_samples):
    from ntt_script import transform_script, verification_equation_script
    from shake_script import shake256_script
    from test_mldsa import equation_fixture

    key, _, _ = equation_fixture()
    return {
        "arithmetic_script_bytes": {
            label: {"ntt": len(transform_script(signed_residues=enabled)),
                    "inverse_ntt": len(transform_script(inverse=True, signed_residues=enabled)),
                    "fixed_key_equation": len(verification_equation_script(key, signed_residues=enabled))}
            for label, enabled in (("canonical", False), ("signed_residues", True))
        },
        "shake256_832_to_32_script_bytes": len(shake256_script(832, 32)),
    }

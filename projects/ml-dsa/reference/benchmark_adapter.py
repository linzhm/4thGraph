"""Pure ML-DSA-44 benchmark fixtures with the independent OpenSSL signer."""
import os

from mldsa import DIGEST_BYTES, test_only_vector
from payment import sign_spend
from script import locking_script
from fourthgraph.benchmark.cases import Coin, Template, seed
from fourthgraph.bsv.transaction import Output


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
    from challenge_script import sample_in_ball_script
    from hint_script import apply_hints_script
    from ntt_script import checked_equation_script, transform_script, verification_equation_script
    from script import _compile_payment_lock, _historical_lock, _reconstruct_challenge
    from shake_script import shake256_script
    from signature_script import signature_decode_script
    from test_mldsa import equation_fixture
    from test_payment import TEST_SEED

    key, _, _ = equation_fixture()
    payment_key, _ = test_only_vector(TEST_SEED, bytes(32), openssl=os.environ.get("ML_DSA_OPENSSL", "openssl"))
    previous_challenges = _reconstruct_challenge(payment_key, DIGEST_BYTES, compact=True, optimize=False)
    profiles = (
        ("legacy", False, False, _historical_lock(payment_key, compact=False)),
        ("compact", True, False, _historical_lock(payment_key, compact=True)),
        ("optimized", True, True, locking_script(payment_key)),
    )
    return {
        "arithmetic_script_bytes": {
            label: {
                "ntt": len(transform_script(**options)),
                "inverse_ntt": len(transform_script(inverse=True, **options)),
                "fixed_key_equation": len(verification_equation_script(key, **options)),
            }
            for label, options in (("canonical", {}), ("signed_residues", {"signed_residues": True}),
                                   ("compact", {"compact": True}))
        },
        "checked_equation_script_bytes": len(checked_equation_script(key)),
        "forth_lock_with_previous_verifier_bytes": len(_compile_payment_lock(previous_challenges)),
        "shake256_832_to_32_script_bytes": len(shake256_script(832, 32)),
        "payment_script_bytes": {
            label: {
                "signature_decode": len(signature_decode_script(compact=compact, signed_response=optimize)),
                "sample_in_ball": len(sample_in_ball_script(compact=compact, optimize=optimize)),
                "apply_hints": len(apply_hints_script(compact=compact)),
                "shake256_832_to_32": len(shake256_script(832, 32, compact=compact, optimize=optimize)),
                "payment_lock": len(lock),
            }
            for label, compact, optimize, lock in profiles
        },
    }

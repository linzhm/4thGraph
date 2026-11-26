"""Pure ML-DSA-44 benchmark fixtures with the independent OpenSSL signer."""
import os

from mldsa import DIGEST_BYTES, test_only_vector
from payment import sign_spend
from script import locking_script
from fourthgraph.benchmark.cases import Coin, Template, seed
from fourthgraph.bsv.pushtx import check_binding
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
    from hint_script import apply_hints_script, apply_sparse_hints_script
    from ntt_script import checked_equation_script, transform_script, verification_equation_script
    from script import (
        COMPANION_CODE, _VerifierVersion, _compile_payment_lock, _historical_forth_lock,
        _historical_lock, _reconstruct_challenge, _shake_options,
    )
    from shake_script import keccak_f1600_script, shake256_script
    from signature_script import signature_decode_script
    from test_mldsa import equation_fixture
    from test_payment import TEST_SEED

    key, _, _ = equation_fixture()
    payment_key, _ = test_only_vector(TEST_SEED, bytes(32), openssl=os.environ.get("ML_DSA_OPENSSL", "openssl"))
    previous_challenges = _reconstruct_challenge(payment_key, DIGEST_BYTES, version=_VerifierVersion.COMPACT)
    profiles = (
        ("legacy", _VerifierVersion.ORIGINAL, _historical_lock(payment_key, compact=False)),
        ("compact", _VerifierVersion.COMPACT, _historical_lock(payment_key, compact=True)),
        ("v0.2.0", _VerifierVersion.V02, _historical_forth_lock(payment_key, version=_VerifierVersion.V02)),
        ("v0.3.0", _VerifierVersion.V03, _historical_forth_lock(payment_key, version=_VerifierVersion.V03)),
        ("v0.4.0", _VerifierVersion.V04, _historical_forth_lock(payment_key, version=_VerifierVersion.V04)),
        ("optimized", _VerifierVersion.V05, locking_script(payment_key)),
    )
    payment_sizes = {}
    for label, version, lock in profiles:
        shake = _shake_options(version)
        compact = shake["compact"]
        sparse = version >= _VerifierVersion.V04
        signature = signature_decode_script(compact=compact, signed_response=version >= _VerifierVersion.V02,
                                            sparse_hints=sparse)
        hints = apply_sparse_hints_script() if sparse else apply_hints_script(compact=compact)
        payment_sizes[label] = {
            "keccak_f1600": len(keccak_f1600_script(**shake)),
            "signature_decode": len(signature),
            "sample_in_ball": len(sample_in_ball_script(**shake)),
            "apply_hints": len(hints),
            "shake256_832_to_32": len(shake256_script(832, 32, **shake)),
            "input_binding": len(check_binding(COMPANION_CODE, compact=version >= _VerifierVersion.V05)),
            "payment_lock": len(lock),
        }
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
        "v02_checked_equation_script_bytes": len(checked_equation_script(key, packed=False)),
        "forth_lock_with_previous_verifier_bytes": len(_compile_payment_lock(previous_challenges)),
        "shake256_832_to_32_script_bytes": len(shake256_script(832, 32)),
        "payment_script_bytes": payment_sizes,
    }

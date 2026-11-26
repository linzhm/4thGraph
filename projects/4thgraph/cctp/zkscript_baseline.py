"""Build upstream zkscript verifiers for the original CCTP key and proofs."""

from inspect import getfile
from pathlib import Path
import subprocess

from elliptic_curves.instantiations.bls12_381.bls12_381 import (
    BLS12_381, Fq, Fq2, ProofBls12381, VerifyingKeyBls12381,
)
from src.zkscript.groth16.bls12_381.bls12_381 import bls12_381
from src.zkscript.script_types.locking_keys.groth16 import Groth16LockingKey
from src.zkscript.script_types.locking_keys.groth16_proj import Groth16ProjLockingKey
from src.zkscript.script_types.unlocking_keys.groth16 import Groth16UnlockingKey
from src.zkscript.script_types.unlocking_keys.groth16_proj import Groth16ProjUnlockingKey


def g1(point):
    if point is None:
        return BLS12_381.g1_curve.get_generator().multiply(0)
    x, y = point
    return BLS12_381.g1_curve(Fq(x), Fq(y), False)


def g2(point):
    x, y = point
    return BLS12_381.g2_curve(Fq2.from_list(list(x)), Fq2.from_list(list(y)), False)


def revision(value):
    checkout = Path(getfile(type(value))).resolve().parent
    result = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if not result.returncode else None


class ZkScript:
    """The native affine-lock and projective-lock upstream profiles."""

    def __init__(self, key):
        vk = VerifyingKeyBls12381(g1(key.alpha), g2(key.beta), g2(key.gamma), g2(key.delta),
                                  [g1(point) for point in key.ic])
        self.cache = vk.prepare()
        self.key = vk.prepare_for_zkscript(self.cache)
        self.max_multipliers = [1 << 128] * 2
        self.revisions = {"zkscript_package": revision(bls12_381), "elliptic_curves_package": revision(BLS12_381)}

    def lock(self, mode):
        key = self.key
        args = dict(alpha_beta=key.alpha_beta, minus_gamma=key.minus_gamma,
                    minus_delta=key.minus_delta, gamma_abc=key.gamma_abc)
        options = dict(modulo_threshold=1, max_multipliers=self.max_multipliers,
                       extractable_inputs=0, check_constant=True, clean_constant=True)
        if mode == "zkscript-affine":
            lock = bls12_381.groth16_verifier(Groth16LockingKey(
                **args, gradients_pairings=[key.gradients_minus_gamma, key.gradients_minus_delta],
                has_precomputed_gradients=True,
            ), **options)
        else:
            lock = bls12_381.groth16_verifier_proj(Groth16ProjLockingKey(**args), **options)
        return lock.raw_serialize()

    def unlock(self, mode, signals, proof):
        upstream = ProofBls12381(g1(proof.a), g2(proof.b), g1(proof.c))
        prepared = upstream.prepare_for_zkscript(self.cache, list(signals))
        args = dict(groth16_model=bls12_381, pub=prepared.public_statements,
                    A=prepared.a, B=prepared.b, C=prepared.c,
                    max_multipliers=self.max_multipliers, inverse_miller_output=prepared.inverse_miller_loop)
        if mode == "zkscript-affine":
            key = Groth16UnlockingKey.from_data(
                **args, gradients_pairings=[prepared.gradients_b, prepared.gradients_minus_gamma,
                                            prepared.gradients_minus_delta],
                gradients_multiplications=prepared.gradients_multiplications,
                gradients_additions=prepared.gradients_additions,
                gradient_gamma_abc_zero=prepared.gradient_gamma_abc_zero,
                has_precomputed_gradients=False,
            )
        else:
            key = Groth16ProjUnlockingKey.from_data(**args)
        return key.to_unlocking_script(bls12_381, True, 0).raw_serialize()

"""Build the selected upstream affine and projective locks for the shared fixture."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from elliptic_curves.instantiations.bls12_381.bls12_381 import (
    BLS12_381 as curve, ProofBls12381, VerifyingKeyBls12381,
)
from src.zkscript.groth16.bls12_381.bls12_381 import bls12_381
from src.zkscript.script_types.locking_keys.groth16 import Groth16LockingKey
from src.zkscript.script_types.locking_keys.groth16_proj import Groth16ProjLockingKey
from src.zkscript.script_types.unlocking_keys.groth16 import Groth16UnlockingKey
from src.zkscript.script_types.unlocking_keys.groth16_proj import Groth16ProjUnlockingKey


NCHAIN_REVISION = "fc20fb743edbc5bc5aba9d16625d50d1f50a3ef4"
PROJECT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT.parent / "proof-counter/versions/v0.1.0/bls12381-counter.json"
BOUNDS = [1 << bits for bits in (32, 1, 32, 2, 2)]
THRESHOLD = 6400


def g1(point):
    return curve.g1_curve(*(curve.g1_field.from_list([int(c)]) for c in point[:2]), False)


def g2(point):
    return curve.g2_curve(*(curve.g2_field.from_list(list(map(int, c))) for c in point[:2]), False)


def unlocking(layout, proof, statement):
    kwargs = dict(groth16_model=bls12_381, pub=statement.public_statements, A=proof.a, B=proof.b, C=proof.c,
                  max_multipliers=BOUNDS, inverse_miller_output=proof.inverse_miller_loop)
    if layout == "projective":
        key = Groth16ProjUnlockingKey.from_data(**kwargs)
    else:
        key = Groth16UnlockingKey.from_data(
            **kwargs, gradients_pairings=[proof.gradients_b, proof.gradients_minus_gamma, proof.gradients_minus_delta],
            gradients_multiplications=statement.gradients_multiplications,
            gradients_additions=statement.gradients_additions, gradient_gamma_abc_zero=statement.gradient_gamma_abc_zero,
            has_precomputed_gradients=layout == "affine-witness-gradients",
        )
    return key.to_unlocking_script(bls12_381, True, 0).raw_serialize().hex()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if revision != NCHAIN_REVISION or subprocess.check_output(["git", "status", "--porcelain", "-uno"]):
        cli.error(f"run from an unmodified nChain checkout at {NCHAIN_REVISION}")

    fixture_bytes = FIXTURE.read_bytes()
    fixture = json.loads(fixture_bytes)
    key = fixture["verification_key"]
    alpha, beta = g1(key["vk_alpha_1"]), g2(key["vk_beta_2"])
    vk = VerifyingKeyBls12381(alpha, beta, g2(key["vk_gamma_2"]), g2(key["vk_delta_2"]), list(map(g1, key["IC"])))
    prepared = vk.prepare()
    pvk = vk.prepare_for_zkscript(prepared)
    common_key = dict(alpha_beta=curve.pairing([alpha], [beta]).to_list(), minus_gamma=pvk.minus_gamma,
                      minus_delta=pvk.minus_delta, gamma_abc=pvk.gamma_abc)
    statements = []
    for name in ("wrap", "other"):
        case = fixture[name]
        proof = case["proof"]
        points = ProofBls12381(g1(proof["pi_a"]), g2(proof["pi_b"]), g1(proof["pi_c"]))
        statements.append(points.prepare_for_zkscript(prepared, list(map(int, case["public"]))))

    options = dict(max_multipliers=BOUNDS, modulo_threshold=THRESHOLD, extractable_inputs=0,
                   check_constant=True, clean_constant=True)
    locks = {}
    for name, in_lock in (("affine-lock-gradients", True), ("affine-witness-gradients", False)):
        affine_key = Groth16LockingKey(**common_key,
                                      gradients_pairings=[pvk.gradients_minus_gamma, pvk.gradients_minus_delta],
                                      has_precomputed_gradients=in_lock)
        locks[name] = bls12_381.groth16_verifier(affine_key, **options)
    locks["projective"] = bls12_381.groth16_verifier_proj(Groth16ProjLockingKey(**common_key), **options)

    variants = {}
    for name, lock in locks.items():
        variants[name] = {"lock": lock.raw_serialize().hex(), "statements": [
            {"witness": unlocking(name, statement, statement), "crossed": unlocking(name, statement, other)}
            for statement, other in zip(statements, reversed(statements), strict=True)
        ]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    evidence = dict(revision=revision, fixture_sha256=sha256(fixture_bytes).hexdigest(), threshold=THRESHOLD,
                    variants=variants)
    args.output.write_text(json.dumps(evidence) + "\n")


if __name__ == "__main__":
    main()

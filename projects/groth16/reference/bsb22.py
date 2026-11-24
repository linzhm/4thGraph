"""Reusable Bitcoin Script verifier for gnark's single-commitment BSB22 profile.

The two public inputs are unsigned 128-bit limbs supplied by the caller.
This module implements proof verification. Protocol callers determine and
authenticate the public inputs and transaction context.
"""

from dataclasses import dataclass, replace

from bsb22_pedersen import knowledge_fields, require_knowledge
from bsb22_short_mimc import BLOCK_BITS, commitment_challenge
from compiler import Program
from public_inputs import require_affine_msm
from shared.script import number
from verifier import Curve, Host, Proof, check_point_host, locking_script, unlocking_fields, unlocking_script


@dataclass(frozen=True)
class CommitmentRelation:
    generator: tuple
    sigma_neg: tuple

    def __post_init__(self):
        check_point_host(self.generator, twist=True)
        check_point_host(self.sigma_neg, twist=True)

    def __call__(self, program, ic, high, low, claimed_x, claimed_y):
        constant, high_base, low_base, challenge_base = ic
        commitment = tuple(program.wire_field() for _ in range(2))
        proof = tuple(program.wire_field() for _ in range(2))
        residue = tuple(tuple(program.wire_field() for _ in range(2)) for _ in range(6))
        require_knowledge(program, commitment, proof, residue, self.generator, self.sigma_neg)
        challenge = commitment_challenge(program, commitment)
        terms = ((high, high_base, 128), (low, low_base, 128), (challenge, challenge_base, BLOCK_BITS))
        return require_affine_msm(program, constant, terms, claimed_x, claimed_y, checked_offset=commitment)


@dataclass(frozen=True)
class CommittedProof:
    proof: Proof
    commitment: tuple
    knowledge_proof: tuple


def verifier_lock(key, relation):
    """Check two authenticated limbs, a single commitment, and the Groth16 proof."""
    return locking_script(key, None, projective_g1=True, projective_g2=True,
                          reuse_constants=True, input_relation=relation)[0]


def verifier_fields(key, relation, signals, proof):
    """Return witness fields in the same order as the extended verifier expects."""
    high, low = signals
    if any(type(value) is not int or not 0 <= value < 2**128 for value in signals):
        raise ValueError("expected two unsigned 128-bit public signals")
    host = Curve(Host())
    challenge = commitment_challenge(Program(), proof.commitment)
    constant, *bases = key.ic
    point = constant_with_commitment = host.add_host(constant, proof.commitment)
    inputs = high, low, challenge
    for base, value in zip(bases, inputs, strict=True):
        point = host.add_host(point, host.mul_host(base, value))
    transformed_key = replace(key, ic=(constant_with_commitment, *bases))
    fields = unlocking_fields(transformed_key, inputs, proof.proof, projective_g1=True, projective_g2=True)
    knowledge = knowledge_fields(proof.commitment, proof.knowledge_proof, relation.generator, relation.sigma_neg)
    return (*(point or (0, 0)), *fields, *knowledge)


def standalone_witness(key, relation, signals, proof):
    """Push public values for isolated verification; transactions must authenticate them."""
    return unlocking_script(verifier_fields(key, relation, signals, proof)) + b"".join(map(number, signals))

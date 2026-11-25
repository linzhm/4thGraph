"""Single-commitment BSB22 knowledge proof pairing in BSV Script.

The caller still needs to bind the same commitment point to the Groth16
public-input calculation, including the gnark hash-to-field transcript.
"""

from functools import lru_cache

from compiler import Program
from field import EXTENSION_ORDER, RESIDUE_INVERSE, Tower, U
from verifier import (
    Curve, Host, check_g1_projective, check_point_host, fixed_miller, prepared_lines, unlocking_script,
)


def _miller_product(tower, commitment, proof, generator, sigma_neg):
    return tower.mul12(
        fixed_miller(tower, commitment, prepared_lines(sigma_neg)),
        fixed_miller(tower, proof, prepared_lines(generator)),
    )


@lru_cache(maxsize=8)
def knowledge_lock(generator, sigma_neg):
    """Require e(commitment, sigma_neg) * e(proof, generator) == 1.

    The two affine witness points must be finite. Both fixed G2 points are
    checked when creating the lock. This function builds a standalone check.
    """
    check_point_host(generator, twist=True)
    check_point_host(sigma_neg, twist=True)
    program = Program()
    commitment = tuple(program.wire_field() for _ in range(2))
    proof = tuple(program.wire_field() for _ in range(2))
    residue = tuple(tuple(program.wire_field() for _ in range(2)) for _ in range(6))
    require_knowledge(program, commitment, proof, residue, generator, sigma_neg)
    return program.compile(reuse_constants=True)[0]


def require_knowledge(program, commitment, proof, residue, generator, sigma_neg):
    """Assert finite G1 points and their PoK product using trusted fixed G2 points."""
    tower = Tower(program)
    curve = Curve(program)
    check_g1_projective(curve, commitment)
    check_g1_projective(curve, proof)
    product = _miller_product(tower, commitment, proof, generator, sigma_neg)
    product = tower.mul12(tower.mul12(product, tower.power12(residue, U)), tower.frobenius(residue))
    for coefficient in product[1::2]:
        for limb in coefficient:
            program.zero(limb)
    nonzero = 0
    for coefficient in product[::2]:
        for limb in coefficient:
            nonzero = program.add(nonzero, program.nonzero(limb))
    program.require(nonzero)


def knowledge_witness(commitment, proof, generator, sigma_neg):
    return unlocking_script(knowledge_fields(commitment, proof, generator, sigma_neg))


def knowledge_fields(commitment, proof, generator, sigma_neg):
    check_point_host(commitment)
    check_point_host(proof)
    tower = Tower(Host())
    product = _miller_product(tower, commitment, proof, generator, sigma_neg)
    residue = tower.power12(product, EXTENSION_ORDER - RESIDUE_INVERSE)
    return (*commitment, *proof, *(limb for coefficient in residue for limb in coefficient))

"""Use the BSV Groth16 core with gnark's single BSB22 commitment profile."""

from dataclasses import dataclass, replace

from compiler import Program
from field import R
from public_inputs import require_affine_msm
from shared.script import asm, number, push
from snarkjs_adapter import point, scalar
from transfer import digest_limbs_script
from verifier import Curve, Host, Proof, VerificationKey, check_point_host, locking_script, unlocking_fields, unlocking_script

from pedersen import knowledge_fields, require_knowledge
from short_mimc import BLOCK_BITS, commitment_challenge

RECURSION_DOMAIN = b"BSV/CCTP/recursion-spike/v1\x00"


def recursive_digest_script():
    """Consume already authenticated [parent0, parent1, current] digests."""
    size_check = asm("OP_SIZE 32 OP_NUMEQUALVERIFY")
    return (size_check + asm("OP_TOALTSTACK") + size_check + asm("OP_SWAP") + size_check
            + asm("OP_SWAP OP_CAT OP_FROMALTSTACK OP_SWAP OP_CAT")
            + push(RECURSION_DOMAIN) + asm("OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script())


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


def load_artifact(data):
    """Decode a fixture exported by the pinned recursion experiment."""
    if (data["format"] != "CCTP recursion experiment v1" or data["protocol"] != "gnark Groth16 BSB22"
            or data["curve"] != "bls12-381" or data["hash_to_field"] != "gnark NewShort BLS12-381 MiMC"
            or data["committed_public_indexes"] != []):
        raise ValueError("expected the single-commitment, zero-index short MiMC profile")
    key = VerificationKey(point(data["g1_alpha"]), point(data["g2_beta"], twist=True),
                          point(data["g2_gamma"], twist=True), point(data["g2_delta"], twist=True),
                          tuple(point(value, allow_infinity=True) for value in data["ic"]))
    if len(key.ic) != 4 or len(data["public_signals"]) != 2:
        raise ValueError("invalid Groth16 public input shape")
    relation = CommitmentRelation(point(data["commitment_g2"], twist=True),
                                  point(data["commitment_g2_sigma_neg"], twist=True))
    proof = Proof(point(data["proof_a"]), point(data["proof_b"], twist=True), point(data["proof_c"]))
    committed = CommittedProof(proof, point(data["commitment"]), point(data["commitment_knowledge_proof"]))
    signals = tuple(scalar(value, R) for value in data["public_signals"])
    return key, relation, signals, committed

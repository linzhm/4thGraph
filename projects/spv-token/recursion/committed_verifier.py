"""CCTP proof artifact and recursive statement adapter for the BSB22 verifier."""

from bsb22 import CommitmentRelation, CommittedProof, standalone_witness, verifier_fields, verifier_lock
from field import R
from shared.script import asm, push
from snarkjs_adapter import point, scalar
from transfer import digest_limbs_script
from verifier import Proof, VerificationKey


RECURSION_DOMAIN = b"BSV/CCTP/recursion-spike/v1\x00"


def recursive_digest_script():
    """Consume already authenticated [parent0, parent1, current] digests."""
    size_check = asm("OP_SIZE 32 OP_NUMEQUALVERIFY")
    return (size_check + asm("OP_TOALTSTACK") + size_check + asm("OP_SWAP") + size_check
            + asm("OP_SWAP OP_CAT OP_FROMALTSTACK OP_SWAP OP_CAT")
            + push(RECURSION_DOMAIN) + asm("OP_SWAP OP_CAT OP_HASH256") + digest_limbs_script())


def load_verifying_key(data):
    """Decode the supported BSB22 key and its commitment parameters."""
    if (data["format"] != "CCTP recursion experiment v1" or data["protocol"] != "gnark Groth16 BSB22"
            or data["curve"] != "bls12-381" or data["hash_to_field"] != "gnark NewShort BLS12-381 MiMC"
            or data["committed_public_indexes"] != []):
        raise ValueError("expected the single-commitment, zero-index short MiMC profile")
    key = VerificationKey(point(data["g1_alpha"]), point(data["g2_beta"], twist=True),
                          point(data["g2_gamma"], twist=True), point(data["g2_delta"], twist=True),
                          tuple(point(value, allow_infinity=True) for value in data["ic"]))
    if len(key.ic) != 4:
        raise ValueError("invalid Groth16 public input shape")
    relation = CommitmentRelation(point(data["commitment_g2"], twist=True),
                                  point(data["commitment_g2_sigma_neg"], twist=True))
    return key, relation


def load_artifact(data):
    """Decode a fixture exported by the pinned recursion experiment."""
    key, relation = load_verifying_key(data)
    if len(data["public_signals"]) != 2:
        raise ValueError("invalid Groth16 public input shape")
    proof = Proof(point(data["proof_a"]), point(data["proof_b"], twist=True), point(data["proof_c"]))
    committed = CommittedProof(proof, point(data["commitment"]), point(data["commitment_knowledge_proof"]))
    signals = tuple(scalar(value, R) for value in data["public_signals"])
    return key, relation, signals, committed

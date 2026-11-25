"""Recover a v3 prover input from the verifier witness in a confirmed transaction."""

from committed_verifier import load_artifact, load_verifying_key, verifier_fields
from field import Q
from shared.script import decode_num, number
from verifier import unlocking_script


def _proof_coordinates(witness):
    # v3 pushes the field list in reverse: affine MSM (2), A/B/C (8),
    # pairing residue (12), commitment and knowledge proof (4), and their residue (12).
    fields = []
    offset = 0
    for _ in range(2 + 8 + 12 + 4 + 12):
        if offset >= len(witness):
            raise ValueError("truncated v3 proof witness")
        start, opcode = offset, witness[offset]
        offset += 1
        if 0 <= opcode <= 48 and offset + opcode <= len(witness):
            value = decode_num(witness[offset:offset + opcode])
            offset += opcode
        elif 0x51 <= opcode <= 0x60:
            value = opcode - 0x50
        else:
            raise ValueError("invalid field push in v3 proof witness")
        if not 0 <= value < Q or number(value) != witness[start:offset]:
            raise ValueError("noncanonical v3 proof field")
        fields.append(value)
    fields.reverse()
    return fields, offset


def chain_prior_artifact(verifier, key_artifact, tx, funding):
    """Rebuild native proof data; the caller authenticates inclusion and receipt eligibility.

    The recursive prover verifies the recovered proof with its own key before using it.
    Only public deployment parameters and the actual transaction and funding are needed.
    """
    if (key_artifact["continuity_key_digest"] != verifier.key_digest.hex() or
            load_verifying_key(key_artifact) != (verifier.key, verifier.commitment)):
        raise ValueError("public parameters differ from the configured continuity verifier")
    receipt, context = verifier.context(tx, funding)
    asset = verifier.asset.asset_id()
    signals = receipt.signals(asset, verifier.key_digest, context)
    witness = tx.inputs[verifier.verifier_input_index(tx)].script
    return _recover(key_artifact, signals, witness)


def _recover(key_artifact, signals, witness):
    fields, end = _proof_coordinates(witness)

    def g1(i):
        return [str(fields[i]), str(fields[i + 1]), "1"]

    artifact = dict(
        key_artifact, public_signals=list(map(str, signals)), proof_a=g1(2),
        proof_b=[[str(fields[4]), str(fields[5])], [str(fields[6]), str(fields[7])], ["1", "0"]],
        proof_c=g1(8), commitment=g1(22), commitment_knowledge_proof=g1(24),
    )
    key, relation, public, proof = load_artifact(artifact)
    if unlocking_script(verifier_fields(key, relation, public, proof)) != witness[:end]:
        raise ValueError("v3 proof fields differ from the actual witness and public statement")
    return artifact

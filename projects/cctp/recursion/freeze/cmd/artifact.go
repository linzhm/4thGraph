package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
)

type proofStatement interface {
	Encode() []byte
	Digest() [32]byte
	Limbs() [2]*big.Int
}

func encodeG1(p bls.G1Affine) [3]string {
	if p.IsInfinity() {
		return [3]string{"0", "1", "0"}
	}
	return [3]string{p.X.String(), p.Y.String(), "1"}
}

func encodeG2(p bls.G2Affine) [3][2]string {
	return [3][2]string{{p.X.A0.String(), p.X.A1.String()}, {p.Y.A0.String(), p.Y.A1.String()}, {"1", "0"}}
}

func keyArtifact(m manifest, vk *native.VerifyingKey) (map[string]any, error) {
	if len(vk.G1.K) != 3+m.Commitments || len(vk.CommitmentKeys) != m.Commitments ||
		len(vk.PublicAndCommitmentCommitted) != m.Commitments {
		return nil, fmt.Errorf("verifying key has the wrong shape for the %s circuit", m.Profile)
	}
	points := make([][3]string, len(vk.G1.K))
	for i, point := range vk.G1.K {
		points[i] = encodeG1(point)
	}
	data := map[string]any{
		"test_only":            m.TestOnly,
		"constraints":          m.Constraints,
		"circuit_sha256":       m.CircuitSHA256,
		"verifying_key_sha256": m.VerifyingSHA256,
		"curve":                "bls12-381",
	}
	switch m.Profile {
	case originProfile, inventoryProfile:
		data["inventory_profile"] = m.Profile
	case conservationProfile:
		data["conservation_profile"] = m.Profile
	case parentCheckpointProfile, tokenCheckpointProfile, backtraceProfile:
		data["parent_checkpoint_profile"] = m.Profile
	default:
		data["freeze_profile"] = m.Profile
	}
	switch m.Profile {
	case originProfile, inventoryProfile, plainProfile, conservationProfile, parentCheckpointProfile, tokenCheckpointProfile, backtraceProfile:
		// Export the affine shape used by snarkjs_adapter, with Fp2 real first.
		format := "CCTP freeze Groth16 artifact v1"
		switch m.Profile {
		case originProfile:
			format = "CCTP inventory origin Groth16 artifact v1"
		case inventoryProfile:
			format = "CCTP inventory payment Groth16 artifact v1"
		case conservationProfile:
			format = "CCTP conservation Groth16 artifact v1"
		case parentCheckpointProfile:
			format = "CCTP parent checkpoint Groth16 artifact v1"
		case tokenCheckpointProfile:
			format = "CCTP token parent checkpoint Groth16 artifact v1"
		case backtraceProfile:
			format = "CCTP parent openings Groth16 artifact v1"
		}
		data["format"], data["protocol"], data["nPublic"] = format, "groth16", 2
		data["vk_alpha_1"], data["vk_beta_2"] = encodeG1(vk.G1.Alpha), encodeG2(vk.G2.Beta)
		data["vk_gamma_2"], data["vk_delta_2"], data["IC"] = encodeG2(vk.G2.Gamma), encodeG2(vk.G2.Delta), points
	case bsb22Profile:
		if len(vk.PublicAndCommitmentCommitted[0]) != 0 {
			return nil, fmt.Errorf("expected no public BSB22 commitment indexes")
		}
		data["format"], data["protocol"] = "CCTP recursion experiment v1", "gnark Groth16 BSB22"
		data["hash_to_field"] = "gnark NewShort BLS12-381 MiMC"
		data["g1_alpha"], data["g2_beta"] = encodeG1(vk.G1.Alpha), encodeG2(vk.G2.Beta)
		data["g2_gamma"], data["g2_delta"], data["ic"] = encodeG2(vk.G2.Gamma), encodeG2(vk.G2.Delta), points
		data["commitment_g2"] = encodeG2(vk.CommitmentKeys[0].G)
		data["commitment_g2_sigma_neg"] = encodeG2(vk.CommitmentKeys[0].GSigmaNeg)
		data["committed_public_indexes"] = []int{}
	default:
		return nil, fmt.Errorf("unrecognized artifact profile %q", m.Profile)
	}
	return data, nil
}

func addProof(data map[string]any, profile string, proof *native.Proof, statement proofStatement) error {
	limbs := statement.Limbs()
	digest := statement.Digest()
	data["public_signals"] = [2]string{limbs[0].String(), limbs[1].String()}
	data["statement"] = hex.EncodeToString(statement.Encode())
	data["statement_digest"] = hex.EncodeToString(digest[:])
	switch profile {
	case originProfile, inventoryProfile, plainProfile, conservationProfile, parentCheckpointProfile, tokenCheckpointProfile, backtraceProfile:
		if len(proof.Commitments) != 0 {
			return fmt.Errorf("plain proof must have no commitment")
		}
		data["pi_a"], data["pi_b"], data["pi_c"] = encodeG1(proof.Ar), encodeG2(proof.Bs), encodeG1(proof.Krs)
	case bsb22Profile:
		if len(proof.Commitments) != 1 {
			return fmt.Errorf("expected one BSB22 proof commitment")
		}
		data["proof_a"], data["proof_b"], data["proof_c"] = encodeG1(proof.Ar), encodeG2(proof.Bs), encodeG1(proof.Krs)
		data["commitment"] = encodeG1(proof.Commitments[0])
		data["commitment_knowledge_proof"] = encodeG1(proof.CommitmentPok)
	default:
		return fmt.Errorf("unrecognized proof profile %q", profile)
	}
	return nil
}

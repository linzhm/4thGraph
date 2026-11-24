package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsGroth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
)

func encodeG1(p bls.G1Affine) [3]string {
	if p.IsInfinity() {
		return [3]string{"0", "1", "0"}
	}
	return [3]string{p.X.String(), p.Y.String(), "1"}
}

func encodeG2(p bls.G2Affine) [3][2]string {
	return [3][2]string{
		{p.X.A0.String(), p.X.A1.String()}, {p.Y.A0.String(), p.Y.A1.String()}, {"1", "0"},
	}
}

func exportOuterProof(path string, vk *blsGroth16.VerifyingKey, proof *blsGroth16.Proof,
	inputs [2]frontend.Variable) error {
	if len(vk.CommitmentKeys) != 1 || len(proof.Commitments) != 1 || len(vk.G1.K) != 4 {
		return fmt.Errorf("unexpected BSB22 artifact shape")
	}
	key := vk.CommitmentKeys[0]
	data := map[string]any{
		"format":                     "CCTP recursion experiment v1",
		"protocol":                   "gnark Groth16 BSB22",
		"curve":                      "bls12-381",
		"hash_to_field":              "gnark NewShort BLS12-381 MiMC",
		"public_signals":             [2]string{inputs[0].(*big.Int).String(), inputs[1].(*big.Int).String()},
		"g1_alpha":                   encodeG1(vk.G1.Alpha),
		"g2_beta":                    encodeG2(vk.G2.Beta),
		"g2_gamma":                   encodeG2(vk.G2.Gamma),
		"g2_delta":                   encodeG2(vk.G2.Delta),
		"ic":                         [4][3]string{encodeG1(vk.G1.K[0]), encodeG1(vk.G1.K[1]), encodeG1(vk.G1.K[2]), encodeG1(vk.G1.K[3])},
		"commitment_g2":              encodeG2(key.G),
		"commitment_g2_sigma_neg":    encodeG2(key.GSigmaNeg),
		"committed_public_indexes":   vk.PublicAndCommitmentCommitted[0],
		"proof_a":                    encodeG1(proof.Ar),
		"proof_b":                    encodeG2(proof.Bs),
		"proof_c":                    encodeG1(proof.Krs),
		"commitment":                 encodeG1(proof.Commitments[0]),
		"commitment_knowledge_proof": encodeG1(proof.CommitmentPok),
	}
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0600)
}

// bsb22_arithmetic creates an independent test proof for two byte-sized factors.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	blsGroth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

type factorCircuit struct {
	Sum     frontend.Variable `gnark:",public"`
	Product frontend.Variable `gnark:",public"`
	X       frontend.Variable
	Y       frontend.Variable
}

func (c *factorCircuit) Define(api frontend.API) error {
	api.ToBinary(c.X, 8)
	api.ToBinary(c.Y, 8)
	challenge, err := api.Compiler().(frontend.Committer).Commit(c.X, c.Y)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(challenge, 0)
	api.AssertIsEqual(api.Add(c.X, c.Y), c.Sum)
	api.AssertIsEqual(api.Mul(c.X, c.Y), c.Product)
	return nil
}

func g1(p bls.G1Affine) [3]string {
	if p.IsInfinity() {
		return [3]string{"0", "1", "0"}
	}
	return [3]string{p.X.String(), p.Y.String(), "1"}
}

func g2(p bls.G2Affine) [3][2]string {
	return [3][2]string{{p.X.A0.String(), p.X.A1.String()}, {p.Y.A0.String(), p.Y.A1.String()}, {"1", "0"}}
}

func generate(path string) error {
	field := ecc.BLS12_381.ScalarField()
	circuit, err := frontend.Compile(field, r1cs.NewBuilder, &factorCircuit{})
	if err != nil {
		return err
	}
	pk, verifyingKey, err := groth16.Setup(circuit)
	if err != nil {
		return err
	}
	witness, err := frontend.NewWitness(&factorCircuit{Sum: 16, Product: 55, X: 5, Y: 11}, field)
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(circuit, pk, witness, recursive.GetNativeProverOptions(field, field))
	if err != nil {
		return err
	}
	public, err := witness.Public()
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, verifyingKey, public, recursive.GetNativeVerifierOptions(field, field)); err != nil {
		return err
	}
	vk, p := verifyingKey.(*blsGroth16.VerifyingKey), proof.(*blsGroth16.Proof)
	if len(vk.G1.K) != 4 || len(vk.CommitmentKeys) != 1 ||
		len(vk.PublicAndCommitmentCommitted) != 1 || len(vk.PublicAndCommitmentCommitted[0]) != 0 ||
		len(p.Commitments) != 1 {
		return fmt.Errorf("unexpected BLS12-381 BSB22 shape")
	}
	ck := vk.CommitmentKeys[0]
	data := map[string]any{
		"format": "BLS12-381 BSB22 factor fixture v1", "public_inputs": [2]string{"16", "55"},
		"alpha": g1(vk.G1.Alpha), "beta": g2(vk.G2.Beta), "gamma": g2(vk.G2.Gamma), "delta": g2(vk.G2.Delta),
		"ic":            [4][3]string{g1(vk.G1.K[0]), g1(vk.G1.K[1]), g1(vk.G1.K[2]), g1(vk.G1.K[3])},
		"commitment_g2": g2(ck.G), "commitment_g2_sigma_neg": g2(ck.GSigmaNeg),
		"a": g1(p.Ar), "b": g2(p.Bs), "c": g1(p.Krs), "commitment": g1(p.Commitments[0]), "pok": g1(p.CommitmentPok),
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: bsb22_arithmetic NEW-FIXTURE.json")
		os.Exit(2)
	}
	if err := generate(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

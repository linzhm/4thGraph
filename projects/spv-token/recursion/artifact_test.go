package main

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	blsGroth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

type artifactSmoke struct {
	High frontend.Variable `gnark:",public"`
	Low  frontend.Variable `gnark:",public"`
	X    frontend.Variable
	Y    frontend.Variable

	requireY bool `gnark:"-"`
}

func (c *artifactSmoke) Define(api frontend.API) error {
	commitment, err := api.Compiler().(frontend.Committer).Commit(c.X, c.Y)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	api.AssertIsEqual(api.Mul(c.X, c.Y), api.Add(c.High, c.Low))
	if c.requireY {
		api.AssertIsDifferent(c.Y, 0)
	}
	return nil
}

func TestCommittedArtifact(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &artifactSmoke{})
	if err != nil {
		t.Fatal(err)
	}
	parameters := filepath.Join(t.TempDir(), "setup")
	_, _, err = provingSetup(ccs, parameters)
	if err != nil {
		t.Fatal(err)
	}
	// Compile independently as a later process would do before reopening its cache.
	ccs, err = frontend.Compile(field, r1cs.NewBuilder, &artifactSmoke{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := provingSetup(ccs, parameters)
	if err != nil {
		t.Fatal(err)
	}
	context := doubleSHA([]byte("current"))
	parents := [2][]byte{[]byte("parent 0"), []byte("parent 1")}
	signals := commitment(context[:], parents)
	sum := new(big.Int).Add(signals[0].(*big.Int), signals[1].(*big.Int))
	w, err := frontend.NewWitness(&artifactSmoke{High: signals[0], Low: signals[1], X: 1, Y: sum}, field)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w, recursive.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatal(err)
	}
	public, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public, recursive.GetNativeVerifierOptions(field, field)); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("CCTP_BSB22_SMOKE_ARTIFACT")
	if path == "" {
		path = filepath.Join(t.TempDir(), "bsb22-smoke.json")
	}
	if err := exportOuterProof(path, vk.(*blsGroth16.VerifyingKey), proof.(*blsGroth16.Proof), signals); err != nil {
		t.Fatal(err)
	}
	other, err := frontend.Compile(field, r1cs.NewBuilder, &artifactSmoke{requireY: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = provingSetup(other, parameters); err == nil || !strings.Contains(err.Error(), "different constraint system") {
		t.Fatalf("reused a setup for a changed circuit: %v", err)
	}
}

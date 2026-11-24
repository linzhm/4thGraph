package main

import (
	"crypto/sha256"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

// dispatchFixture yields a known statement under independent keys. It lets the
// continuity solver isolate key dispatch from the million-constraint setup.
type dispatchFixture struct {
	High, Low frontend.Variable `gnark:",public"`
	Secret    frontend.Variable
}

func (c *dispatchFixture) Define(api frontend.API) error {
	challenge, err := api.Compiler().(frontend.Committer).Commit(c.Secret)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(challenge, 0)
	api.AssertIsEqual(c.High, c.Secret)
	api.AssertIsEqual(c.Low, api.Add(c.Secret, 1))
	return nil
}

func typedFixture(t *testing.T) (*native.VerifyingKey, issuedProof) {
	t.Helper()
	field := fr.Modulus()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &dispatchFixture{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&dispatchFixture{High: 42, Low: 43, Secret: 42}, field)
	if err != nil {
		t.Fatal(err)
	}
	p, err := groth16.Prove(ccs, pk, witness, recursive.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	digest[15], digest[31] = 42, 43
	nvk := vk.(*native.VerifyingKey)
	if err := nativeVerify(nvk, p.(*native.Proof), digest); err != nil {
		t.Fatal(err)
	}
	typed, err := recursive.ValueOfProof[G1, G2](p)
	if err != nil {
		t.Fatal(err)
	}
	return nvk, issuedProof{typed, digest}
}

func TestIndependentSelfKeyDispatch(t *testing.T) {
	if os.Getenv("CCTP_CONTINUITY_SOLVER_TEST") != "1" {
		t.Skip("set CCTP_CONTINUITY_SOLVER_TEST=1 to compile the full continuity constraints")
	}
	s, _, err := compile()
	if err != nil {
		t.Fatal(err)
	}
	key, prior := typedFixture(t)
	_, foreign := typedFixture(t)
	if prior.digest != foreign.digest {
		t.Fatal("foreign proof must use the identical public digest")
	}
	if err := s.useKey(key); err != nil {
		t.Fatal(err)
	}
	asset := sha256.Sum256([]byte("dispatch fixture asset"))
	context := sha256.Sum256([]byte("dispatch fixture context"))
	for _, ps := range [][]issuedProof{nil, {prior}, {prior, prior}} {
		statement := s.transcript(asset, context, ps...)
		if err := s.solve("pinned self key with valid shape", s.makeWitness(statement, ps...), true); err != nil {
			t.Fatal(err)
		}
	}
	statement := s.transcript(asset, context, prior)
	if err := s.solve("foreign proof for identical digest", s.makeWitness(statement, foreign), false); err != nil {
		t.Fatal(err)
	}
}

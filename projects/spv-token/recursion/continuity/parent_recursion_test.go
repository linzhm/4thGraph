package main

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

// literalParentStatement makes real BSB22 fixture proofs for the same two
// public limbs the recursive verification gadget expects.
type literalParentStatement struct {
	Public [2]frontend.Variable `gnark:",public"`
	Value  [2]frontend.Variable
}

func (c *literalParentStatement) Define(api frontend.API) error {
	challenge, err := api.Compiler().(frontend.Committer).Commit(c.Value[:]...)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(challenge, 0)
	for i, value := range c.Value {
		api.AssertIsEqual(c.Public[i], value)
	}
	return nil
}

type authenticatedParentRecursionFixture struct {
	Parents [2]parentContextFixture
	Chain   Circuit
}

func (c *authenticatedParentRecursionFixture) Define(api frontend.API) error {
	api.AssertIsEqual(c.Chain.Count, len(c.Parents))
	for i := range c.Parents {
		digest, err := c.Parents[i].deriveDigest(api, c.Chain.Asset, c.Chain.SelfID)
		if err != nil {
			return err
		}
		for j, value := range digest {
			api.AssertIsEqual(c.Chain.Prior[i][j], value)
			api.AssertIsEqual(c.Parents[i].Digest[j], value)
		}
	}
	return c.Chain.Define(api)
}

func TestReconstructedParentsFeedTheRecursiveVerifier(t *testing.T) {
	if os.Getenv("CCTP_CONTINUITY_SOLVER_TEST") != "1" {
		t.Skip("set CCTP_CONTINUITY_SOLVER_TEST=1 to compile the full continuity constraints")
	}
	field := fr.Modulus()
	source, err := frontend.Compile(field, r1cs.NewBuilder, &literalParentStatement{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(source)
	if err != nil {
		t.Fatal(err)
	}
	pad, _, err := loadPadding()
	if err != nil {
		t.Fatal(err)
	}
	state := &provingState{pad: pad}
	if err := state.useKey(vk.(*native.VerifyingKey)); err != nil {
		t.Fatal(err)
	}
	var asset, context [32]byte
	for i := range asset {
		asset[i], context[i] = byte(i), byte(i+128)
	}
	mintContext := [32]byte(contextFixtureBytes(t, "fe4d7188e253673e7171a797abd358c68fd61b1f92b72cb4bc1afda96694fa06"))
	transferContext := [32]byte(contextFixtureBytes(t, "a61c02463ef026f5ff21a63f0a0c767c898ea98725e124a4734456bfb430a842"))
	transfer := state.transcript(asset, transferContext)
	transfer.Count = 2
	for i := range transfer.Prior[0] {
		transfer.Prior[0][i], transfer.Prior[1][i] = 'c', 't'
	}
	var parents [2]issuedProof
	for i, tParent := range [2]Transcript{state.transcript(asset, mintContext), transfer} {
		digest := tParent.Digest()
		pair := limbs(digest)
		values := [2]frontend.Variable{pair[0], pair[1]}
		w, err := frontend.NewWitness(&literalParentStatement{Public: values, Value: values}, field)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := groth16.Prove(source, pk, w, recursive.GetNativeProverOptions(field, field))
		if err != nil {
			t.Fatal(err)
		}
		if err := nativeVerify(state.vk, proof.(*native.Proof), digest); err != nil {
			t.Fatal(err)
		}
		typed, err := recursive.ValueOfProof[G1, G2](proof)
		if err != nil {
			t.Fatal(err)
		}
		parents[i] = issuedProof{proof: typed, digest: digest}
	}

	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &authenticatedParentRecursionFixture{
		Chain: *circuitTemplate(pad),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("two mixed-shape parent openings and existing recursive verifier: %d constraints", ccs.GetNbConstraints())
	valid := authenticatedParentRecursionFixture{
		Parents: [2]parentContextFixture{
			parentContextAssignment(t, contextFixtureBytes(t, mintParentWire), parents[0].digest, 0, 1),
			parentContextAssignment(t, contextFixtureBytes(t, transferParentWire), parents[1].digest, 1, 0),
		},
		Chain: *state.makeWitness(state.transcript(asset, context, parents[:]...), parents[:]...),
	}
	solve := func(t *testing.T, candidate *authenticatedParentRecursionFixture, accept bool) {
		t.Helper()
		w, challenge, err := solverWitness(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(w, challenge); (err == nil) != accept {
			t.Fatalf("expected accept=%t, solver returned %v", accept, err)
		}
	}
	solve(t, &valid, true)
	t.Run("same key proof for a different parent", func(t *testing.T) {
		substituted := valid
		substituted.Chain.Proofs[0] = parents[1].proof
		solve(t, &substituted, false)
	})
}

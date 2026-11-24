package keycommit

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	frontendcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	recursion "github.com/consensys/gnark/std/recursion/groth16"
)

type sampleCircuit struct {
	A, B   frontend.Variable `gnark:",public"`
	Secret frontend.Variable
}

func (c *sampleCircuit) Define(api frontend.API) error {
	committed, err := api.Compiler().(frontend.Committer).Commit(c.Secret)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(committed, 0)
	api.AssertIsEqual(c.A, api.Mul(c.Secret, c.Secret))
	api.AssertIsEqual(c.B, api.Add(c.Secret, 1))
	return nil
}

type bindingCircuit struct {
	Key    Key
	Digest [2]frontend.Variable `gnark:",public"`
}

func (c *bindingCircuit) Define(api frontend.API) error {
	return Assert(api, &c.Key, c.Digest)
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDigestBindsRecursiveKeyCoordinates(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	inner, err := frontend.Compile(field, r1cs.NewBuilder, &sampleCircuit{})
	check(t, err)
	_, key, err := groth16.Setup(inner)
	check(t, err)
	nativeKey := key.(*native.VerifyingKey)
	digest, err := Digest(nativeKey)
	check(t, err)
	asAssignment := func() Key {
		value, err := recursion.ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](nativeKey)
		check(t, err)
		return value
	}
	assignment := bindingCircuit{
		Key: asAssignment(),
		Digest: [2]frontend.Variable{
			new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:]),
		},
	}
	circuit, err := frontend.Compile(field, r1cs.NewBuilder, &bindingCircuit{Key: Placeholder()})
	check(t, err)
	// Isolate the constraints without performing a setup for this test
	// circuit. Actual setup/proof verification runs in the recursive harness.
	challenge := solver.OverrideHint(solver.GetHintID(frontendcs.Bsb22CommitmentComputePlaceholder),
		func(modulus *big.Int, _ []*big.Int, out []*big.Int) error {
			challenge, err := rand.Int(rand.Reader, modulus)
			if err != nil {
				return err
			}
			out[0].Set(challenge)
			return nil
		})
	solve := func(t *testing.T, value *bindingCircuit) error {
		t.Helper()
		witness, err := frontend.NewWitness(value, field)
		check(t, err)
		_, err = circuit.Solve(witness, challenge)
		return err
	}
	check(t, solve(t, &assignment))

	for _, variant := range []struct {
		name string
		edit func(*Key)
	}{
		{"pairing target", func(v *Key) { v.E.A7 = emulated.ValueOf[sw_bls12381.BaseField](17) }},
		{"IC point", func(v *Key) { v.G1.K[2].X = emulated.ValueOf[sw_bls12381.BaseField](19) }},
		{"commitment key", func(v *Key) { v.CommitmentKeys[0].GSigmaNeg.P.X.A1 = emulated.ValueOf[sw_bls12381.BaseField](23) }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			updated := assignment
			updated.Key = asAssignment()
			variant.edit(&updated.Key)
			if err := solve(t, &updated); err == nil {
				t.Fatal("substituted coordinate accepted")
			}
		})
	}
}

func TestRejectsUncheckedLineAdvice(t *testing.T) {
	key := Placeholder()
	key.G2.GammaNeg = sw_bls12381.NewG2AffineFixedPlaceholder()
	_, err := coordinates(&key)
	if err == nil || !strings.Contains(err.Error(), "lines are forbidden") {
		t.Fatalf("expected rejection of precomputed lines, got %v", err)
	}

	key = Placeholder()
	key.PublicAndCommitmentCommitted[0] = []int{1}
	_, err = coordinates(&key)
	if err == nil || !strings.Contains(err.Error(), "one private BSB22 commitment") {
		t.Fatalf("expected rejection of altered commitment metadata, got %v", err)
	}
}

type proofBindingCircuit struct {
	Key    Key
	Proof  Proof
	Digest [2]frontend.Variable `gnark:",public"`
	Inputs [2]frontend.Variable `gnark:",public"`
}

func (c *proofBindingCircuit) Define(api frontend.API) error {
	return AssertProof(api, &c.Key, c.Proof, c.Digest, c.Inputs)
}

func TestVerifiesAnActualProofUnderTheAuthenticatedKey(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	inner, err := frontend.Compile(field, r1cs.NewBuilder, &sampleCircuit{})
	check(t, err)
	provingKey, nativeKey, err := groth16.Setup(inner)
	check(t, err)
	innerWitness, err := frontend.NewWitness(&sampleCircuit{A: 49, B: 8, Secret: 7}, field)
	check(t, err)
	nativeProof, err := groth16.Prove(inner, provingKey, innerWitness, recursion.GetNativeProverOptions(field, field))
	check(t, err)
	public, err := innerWitness.Public()
	check(t, err)
	check(t, groth16.Verify(nativeProof, nativeKey, public, recursion.GetNativeVerifierOptions(field, field)))

	key, err := recursion.ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](nativeKey)
	check(t, err)
	proof, err := recursion.ValueOfProof[sw_bls12381.G1Affine, sw_bls12381.G2Affine](nativeProof)
	check(t, err)
	digest, err := Digest(nativeKey.(*native.VerifyingKey))
	check(t, err)

	circuit, err := frontend.Compile(field, r1cs.NewBuilder, &proofBindingCircuit{
		Key:   Placeholder(),
		Proof: recursion.PlaceholderProof[sw_bls12381.G1Affine, sw_bls12381.G2Affine](inner),
	})
	check(t, err)
	challenge := solver.OverrideHint(solver.GetHintID(frontendcs.Bsb22CommitmentComputePlaceholder),
		func(modulus *big.Int, _ []*big.Int, out []*big.Int) error {
			challenge, err := rand.Int(rand.Reader, modulus)
			if err != nil {
				return err
			}
			out[0].Set(challenge)
			return nil
		})
	valid := proofBindingCircuit{
		Key: key, Proof: proof, Inputs: [2]frontend.Variable{49, 8},
		Digest: [2]frontend.Variable{
			new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:]),
		},
	}
	witness, err := frontend.NewWitness(&valid, field)
	check(t, err)
	_, err = circuit.Solve(witness, challenge)
	check(t, err)
	invalid := valid
	invalid.Inputs[0] = 50
	witness, err = frontend.NewWitness(&invalid, field)
	check(t, err)
	if _, err := circuit.Solve(witness, challenge); err == nil {
		t.Fatal("prior proof accepted for another statement")
	}
}

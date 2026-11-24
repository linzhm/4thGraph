package parentbinding

import (
	"crypto/sha256"
	"encoding"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

func nativeSHA256State(t *testing.T, fullBlocks []byte) (state [stateSize]byte) {
	t.Helper()
	digest := sha256.New()
	if _, err := digest.Write(fullBlocks); err != nil {
		t.Fatal(err)
	}
	encoded, err := digest.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil || len(encoded) < 36 || string(encoded[:4]) != "sha\x03" {
		t.Fatal("unrecognized standard-library SHA-256 checkpoint format")
	}
	copy(state[:], encoded[4:36])
	return state
}

func TestPrivateSHA256Leaf(t *testing.T) {
	const width = 2
	field := ecc.BLS12_381.ScalarField()
	started := time.Now()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &SHA256Leaf{Blocks: make([]frontend.Variable, width*blockSize)})
	if err != nil {
		t.Fatal(err)
	}
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	if ccs.GetNbPublicVariables() != 6 || ccs.GetNbSecretVariables() != width*blockSize ||
		len(commitments) != 1 || len(commitments[0].GetPublicCommitted()) != 0 {
		t.Fatal("expected five public scalars, private block bytes and one commitment without public indexes")
	}
	t.Logf("blocks=%d constraints=%d public=5 private=%d commitments=1 compile=%s",
		width, ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), time.Since(started))
	raw := make([]byte, 2*width*blockSize)
	for i := range raw {
		raw[i] = byte(i)
	}
	initial := nativeSHA256State(t, nil)
	middle := nativeSHA256State(t, raw[:width*blockSize])
	end := nativeSHA256State(t, raw)
	first, err := AssignSHA256Leaf(0, raw[:width*blockSize], initial, middle)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AssignSHA256Leaf(width, raw[width*blockSize:], middle, end)
	if err != nil {
		t.Fatal(err)
	}
	makeWitness := func(t *testing.T, leaf *SHA256Leaf) witness.Witness {
		t.Helper()
		w, err := frontend.NewWitness(leaf, field)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	firstWitness, secondWitness := makeWitness(t, first), makeWitness(t, second)
	for _, w := range []witness.Witness{firstWitness, secondWitness} {
		if _, err := ccs.Solve(w); err != nil {
			t.Fatal(err)
		}
	}
	public, err := secondWitness.Public()
	if err != nil {
		t.Fatal(err)
	}
	encoded := public.Vector().(fr.Vector)
	expected := [5]*big.Int{new(big.Int).SetBytes(middle[:16]), new(big.Int).SetBytes(middle[16:]),
		new(big.Int).SetBytes(end[:16]), new(big.Int).SetBytes(end[16:]), big.NewInt(width)}
	for i, want := range expected {
		if encoded[i].BigInt(new(big.Int)).Cmp(want) != 0 {
			t.Fatalf("incorrect public scalar at index %d", i)
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*SHA256Leaf)
	}{
		{"non-IV-at-zero", func(c *SHA256Leaf) { c.StartBlock = 0 }},
		{"negative-offset", func(c *SHA256Leaf) { c.StartBlock = -1 }},
		{"offset-out-of-range", func(c *SHA256Leaf) { c.StartBlock = uint64(1) << SHA256BlockIndexBits }},
		{"last-block-wrap", func(c *SHA256Leaf) { c.StartBlock = ^uint32(0) }},
		{"wrong-start", func(c *SHA256Leaf) { c.Start[0] = 0 }},
		{"wrong-end", func(c *SHA256Leaf) { c.End[1] = 0 }},
		{"oversized-limb", func(c *SHA256Leaf) { c.End[0] = new(big.Int).Lsh(big.NewInt(1), 128) }},
		{"wrong-private-block", func(c *SHA256Leaf) { c.Blocks[0] = byte(width*blockSize) ^ 1 }},
		{"nonbyte-block", func(c *SHA256Leaf) { c.Blocks[0] = 256 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := *second
			mutated.Blocks = append([]frontend.Variable(nil), second.Blocks...)
			test.mutate(&mutated)
			if _, err := ccs.Solve(makeWitness(t, &mutated)); err == nil {
				t.Fatal("accepted an invalid segment witness")
			}
		})
	}
	if _, err := AssignSHA256Leaf(0, raw[:blockSize-1], initial, middle); err == nil {
		t.Fatal("accepted a partial block")
	}
	if os.Getenv("CCTP_SHA256_LEAF_NATIVE_TEST") == "1" {
		t.Run("native-proof-binds-offset", func(t *testing.T) {
			relocated := *second
			relocated.StartBlock = 3
			changedOffset, err := makeWitness(t, &relocated).Public()
			if err != nil {
				t.Fatal(err)
			}
			checkNativeSHA256Leaf(t, ccs, firstWitness, secondWitness, changedOffset)
		})
	}
}

func checkNativeSHA256Leaf(t *testing.T, ccs constraint.ConstraintSystem, first, second, changedOffset witness.Witness) {
	t.Helper()
	field := ecc.BLS12_381.ScalarField()
	started := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("setup=%s", time.Since(started))
	prover := recursive.GetNativeProverOptions(field, field)
	verify := recursive.GetNativeVerifierOptions(field, field)
	for i, segment := range []witness.Witness{first, second} {
		started = time.Now()
		proof, err := groth16.Prove(ccs, pk, segment, prover)
		if err != nil {
			t.Fatal(err)
		}
		proveElapsed := time.Since(started)
		public, err := segment.Public()
		if err != nil {
			t.Fatal(err)
		}
		started = time.Now()
		if err := groth16.Verify(proof, vk, public, verify); err != nil {
			t.Fatal(err)
		}
		t.Logf("segment=%d prove=%s verify=%s", i, proveElapsed, time.Since(started))
		if i == 1 && groth16.Verify(proof, vk, changedOffset, verify) == nil {
			t.Fatal("the original proof verified at another nonzero start index")
		}
	}
}

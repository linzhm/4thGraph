package parentbinding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func newCheckpoint(width int, fromIV bool) *Checkpoint {
	return &Checkpoint{Blocks: make([]frontend.Variable, width*blockSize), FromIV: fromIV}
}

func compileCheckpoint(t *testing.T, width int, fromIV bool) constraint.ConstraintSystem {
	t.Helper()
	started := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, newCheckpoint(width, fromIV))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("blocks=%d from_iv=%t constraints=%d public=%d compile=%s", width, fromIV,
		ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1, time.Since(started))
	return ccs
}

func pad(message []byte) []byte {
	padded := make([]byte, (len(message)+9+blockSize-1)/blockSize*blockSize)
	copy(padded, message)
	padded[len(message)] = 0x80
	binary.BigEndian.PutUint64(padded[len(padded)-8:], uint64(len(message))*8)
	return padded
}

func checkpointWitness(t *testing.T, blocks, start, end []byte, fromIV bool) witness.Witness {
	t.Helper()
	assignment := newCheckpoint(len(blocks)/blockSize, fromIV)
	for i, item := range blocks {
		assignment.Blocks[i] = item
	}
	for i := range assignment.Start {
		assignment.Start[i], assignment.End[i] = start[i], end[i]
	}
	w, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestCheckpointConstraintScale(t *testing.T) {
	for _, width := range []int{1, 2, 4, 8} {
		compileCheckpoint(t, width, false)
	}
}

func TestCheckpointNativeProof(t *testing.T) {
	message := []byte("abc")
	blocks := pad(message)
	var iv [stateSize]byte
	for i, word := range initialState {
		binary.BigEndian.PutUint32(iv[4*i:], word)
	}
	digest := sha256.Sum256(message)
	ccs := compileCheckpoint(t, 1, true)
	assignment := checkpointWitness(t, blocks, iv[:], digest[:], true)

	started := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("setup=%s", time.Since(started))
	started = time.Now()
	proof, err := groth16.Prove(ccs, pk, assignment)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prove=%s", time.Since(started))
	public, err := assignment.Public()
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
	t.Logf("verify=%s", time.Since(started))

	blocks[0] ^= 1
	mutated := checkpointWitness(t, blocks, iv[:], digest[:], true)
	mutatedPublic, err := mutated.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, mutatedPublic); err == nil {
		t.Fatal("verified the same proof after changing a public block byte")
	}
}

func TestCheckpointContinuation(t *testing.T) {
	message := append(bytes.Repeat([]byte{'a'}, blockSize), 'b')
	// Unfinalized SHA-256 state after the first 64 'a' bytes, cross-checked
	// against crypto/sha256's marshaled chaining state before padding.
	middle, err := hex.DecodeString("df5bb81ce81e0626fb45a8944fd40f31b25e6816d6d499c1ab90492900635e66")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	blocks := pad(message)[blockSize:]
	ccs := compileCheckpoint(t, 1, false)
	w := checkpointWitness(t, blocks, middle, digest[:], false)
	if _, err := ccs.Solve(w); err != nil {
		t.Fatal(err)
	}

	middle[0] ^= 1
	wrong := checkpointWitness(t, blocks, middle, digest[:], false)
	if _, err := ccs.Solve(wrong); err == nil {
		t.Fatal("accepted a changed start state for the same block and end state")
	}
}

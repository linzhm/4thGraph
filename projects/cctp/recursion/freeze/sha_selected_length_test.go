package freeze

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var selectedTestLengths = [...]int{0, 55, 56, 63, 64, 119, 120, 120}

type selectedLengthSHA256dCircuit struct {
	Message   [120]frontend.Variable
	Selectors [len(selectedTestLengths)]frontend.Variable
	Digest    [32]frontend.Variable `gnark:",public"`
}

func (c *selectedLengthSHA256dCircuit) Define(api frontend.API) error {
	digest, err := SHA256dAtSelectedLength(api, c.Message[:], selectedTestLengths[:], c.Selectors[:])
	if err != nil {
		return err
	}
	for i, value := range digest {
		api.AssertIsEqual(c.Digest[i], value)
	}
	return nil
}

func TestSHA256dSelectedLengthPaddingBoundaries(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &selectedLengthSHA256dCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	assign := func(selected int) *selectedLengthSHA256dCircuit {
		assignment := &selectedLengthSHA256dCircuit{}
		var raw [120]byte
		for i := 0; i < selectedTestLengths[selected]; i++ {
			raw[i] = byte(i*89 + 1)
		}
		for i, value := range raw {
			assignment.Message[i] = value
		}
		for i := range assignment.Selectors {
			assignment.Selectors[i] = 0
		}
		assignment.Selectors[selected] = 1
		first := sha256.Sum256(raw[:selectedTestLengths[selected]])
		for i, value := range sha256.Sum256(first[:]) {
			assignment.Digest[i] = value
		}
		return assignment
	}
	solve := func(assignment *selectedLengthSHA256dCircuit, accepted bool) {
		t.Helper()
		witness, err := frontend.NewWitness(assignment, field)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(witness); (err == nil) != accepted {
			t.Fatalf("unexpected selected-length hash result, wanted valid=%t: %v", accepted, err)
		}
	}
	for i := range selectedTestLengths {
		solve(assign(i), true)
	}
	badTail := assign(1)
	badTail.Message[55] = byte(0x80)
	solve(badTail, false)
	wrongEnd := assign(2)
	wrongEnd.Selectors[2], wrongEnd.Selectors[3] = 0, 1
	solve(wrongEnd, false)
	twoSelected := assign(6)
	twoSelected.Selectors[7] = 1
	solve(twoSelected, false)
	nonbinary := assign(6)
	nonbinary.Selectors[6], nonbinary.Selectors[7] = 2, -1
	solve(nonbinary, false)
}

package inventoryorigin

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func hash(parts ...[]byte) []byte {
	var plain []byte
	for _, part := range parts {
		plain = append(plain, part...)
	}
	first := sha256.Sum256(plain)
	second := sha256.Sum256(first[:])
	return second[:]
}

func testVector(order [4]byte) ([]byte, []byte) {
	var leaves [4][]byte
	var raw []byte
	for i := range leaves {
		leaves[i] = hash([]byte{byte(i)})
		raw = append(raw, leaves[i]...)
	}
	inner := func(a, b []byte) []byte { return hash([]byte{1}, a, b) }
	root := inner(inner(leaves[order[0]], leaves[order[1]]), inner(leaves[order[2]], leaves[order[3]]))
	statement := append([]byte{3}, hash([]byte{4}, raw)...)
	return append(statement, root...), append(raw, order[:]...)
}

func TestExternallyApprovedSourcePermutation(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, statement, opening []byte, ok bool) {
		t.Helper()
		_, assignment, err := Decode(statement, opening)
		if err != nil {
			t.Fatal(err)
		}
		input, err := frontend.NewWitness(assignment, field)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cs.Solve(input)
		if (err == nil) != ok {
			t.Errorf("%s: solved %v; wanted %v", name, err == nil, ok)
		}
	}
	wire, open := testVector([4]byte{2, 0, 3, 1})
	check("valid permutation", wire, open, true)
	for _, index := range []int{1, 33} {
		altered := append([]byte(nil), wire...)
		altered[index] ^= 1
		check("changed public anchor or root", altered, open, false)
	}
	malformed, duplicate := testVector([4]byte{2, 0, 2, 1})
	check("duplicate source index with matching claimed root", malformed, duplicate, false)
}

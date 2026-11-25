package inventoryprove

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func hash256(parts ...[]byte) []byte {
	first := sha256.Sum256(bytes.Join(parts, nil))
	digest := sha256.Sum256(first[:])
	return digest[:]
}

func example(i, j int, quantities [4]uint64, frozen bool) ([]byte, []byte) {
	scope := hash256([]byte("test-only inventory"))
	var states, points, leaves [4][]byte
	for slot := range leaves {
		states[slot] = make([]byte, StateSize)
		binary.LittleEndian.PutUint64(states[slot], quantities[slot])
		binary.LittleEndian.PutUint64(states[slot][8:], 1000)
		states[slot][16] = 2
		if frozen && slot == i {
			states[slot][49] = 1
		}
		points[slot] = append(hash256([]byte{byte(slot)}), 0, 0, 0, 0)
		leaves[slot] = hash256([]byte{0}, scope, points[slot], states[slot])
	}
	left := hash256([]byte{1}, leaves[0], leaves[1])
	right := hash256([]byte{1}, leaves[2], leaves[3])
	root := hash256([]byte{1}, left, right)
	branches := [][]byte{left, right}
	payment := bytes.Join([][]byte{{2}, scope, root, points[i], points[j], states[i], states[j]}, nil)
	var private []byte
	for _, index := range []int{i, j} {
		private = append(private, states[index]...)
		private = append(private, byte(index))
		private = append(private, leaves[index^1]...)
		private = append(private, branches[index/2^1]...)
	}
	return payment, private
}

func TestMembershipAndConservation(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(pay, private []byte, valid bool) {
		t.Helper()
		_, c, err := Decode(pay, private)
		if err != nil {
			t.Fatal(err)
		}
		w, err := frontend.NewWitness(c, field)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ccs.Solve(w)
		if (err == nil) != valid {
			t.Fatalf("expected valid=%v, got %v", valid, err)
		}
	}
	quantities := [4]uint64{10, 11, 12, 13}
	pay, private := example(0, 2, quantities, false)
	check(pay, private, true)
	other, openings := example(1, 3, quantities, false)
	if !bytes.Equal(other[33:65], pay[33:65]) {
		t.Fatal("input choices changed inventory root")
	}
	check(other, openings, true)
	duplicate, repeat := example(0, 0, quantities, false)
	check(duplicate, repeat, false)
	frozen, frozenOpenings := example(0, 2, quantities, true)
	check(frozen, frozenOpenings, false)
	overflow, overflowOpenings := example(0, 2, [4]uint64{math.MaxUint64, 10, 1, 10}, false)
	check(overflow, overflowOpenings, false)
	boundary, boundaryOpenings := example(0, 2, [4]uint64{math.MaxUint64 - 1, 10, 1, 10}, false)
	check(boundary, boundaryOpenings, true)
	badPosition := bytes.Clone(private)
	badPosition[StateSize] = 4
	check(pay, badPosition, false)
	for _, index := range []int{1, 33, 65 + 32, 137, 137 + 8, 137 + 49} { // scope, root, vout, quantity, sats, frozen
		bad := bytes.Clone(pay)
		bad[index] ^= 1
		check(bad, private, false)
	}
	for _, index := range []int{0, 16, 49, 50, 51, OpeningSize + 83} { // leaf, holder, freeze bit, position, both branches
		bad := bytes.Clone(private)
		bad[index] ^= 1
		check(pay, bad, false)
	}
}

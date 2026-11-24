package conservation

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
)

func stateAt(statement *Statement, index int) []byte {
	start := ContextSize + index*freeze.StateSize
	return statement[start : start+freeze.StateSize]
}

func setQuantity(statement *Statement, index int, quantity uint64) {
	binary.LittleEndian.PutUint64(stateAt(statement, index)[freeze.QuantityOffset:], quantity)
}

func conservationVector() Statement {
	var statement Statement
	for i := range statement[:ContextSize] {
		statement[i] = byte(i + 1)
	}
	satoshis := [4]uint64{1250, 1750, 2000, 1000}
	for i, quantity := range [4]uint64{640, 384, 700, 324} {
		state := stateAt(&statement, i)
		binary.LittleEndian.PutUint64(state, satoshis[i])
		state[8], state[freeze.FrozenOffset+1] = 11, 12
		state[freeze.OwnerOffset], state[freeze.OwnerOffset+1] = 2+byte(i%2), byte(i+21)
		setQuantity(&statement, i, quantity)
	}
	return statement
}

func TestConservationCircuit(t *testing.T) {
	started := time.Now()
	ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	if ccs.GetNbPublicVariables() != 3 || ccs.GetNbSecretVariables() != PayloadSize ||
		len(ccs.GetCommitments().(constraint.Groth16Commitments)) != 0 {
		t.Fatal("expected a plain two-public-input proof with no commitment")
	}
	t.Logf("%d constraints, %d private bytes, two public limbs, no commitment, compiled in %s",
		ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), time.Since(started))

	valid := conservationVector()
	parsed, err := ParseStatement(valid.Encode())
	if err != nil || parsed != valid || EncodedSize != 585 {
		t.Fatal("invalid conservation wire round-trip")
	}
	solve := func(t *testing.T, c *Circuit, expectValid bool) {
		t.Helper()
		witness, err := frontend.NewWitness(c, fr.Modulus())
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if _, err := ccs.Solve(witness); (err == nil) != expectValid {
			t.Fatalf("unexpected solver result, wanted valid=%t: %v", expectValid, err)
		}
		if expectValid {
			t.Logf("solved valid statement in %s", time.Since(started))
		}
	}
	t.Run("different-owners-and-quantities", func(t *testing.T) {
		solve(t, valid.Assignment(), true)
	})
	t.Run("maximum-uint64-total", func(t *testing.T) {
		boundary := valid
		for i, qty := range [4]uint64{math.MaxUint64 - 1, 1, 1 << 63, 1<<63 - 1} {
			setQuantity(&boundary, i, qty)
		}
		solve(t, boundary.Assignment(), true)
	})
	for _, item := range []struct {
		name string
		edit func(*Statement)
	}{
		{"extra-quantity", func(s *Statement) { setQuantity(s, 2, 701) }},
		{"extra-satoshis", func(s *Statement) { stateAt(s, 2)[0]++ }},
		{"frozen-input", func(s *Statement) { stateAt(s, 1)[freeze.FrozenOffset] = 1 }},
		{"frozen-successor", func(s *Statement) { stateAt(s, 2)[freeze.FrozenOffset] = 1 }},
		{"foreign-asset", func(s *Statement) { stateAt(s, 2)[8]++ }},
		{"changed-policy", func(s *Statement) { stateAt(s, 3)[freeze.FrozenOffset+1]++ }},
		{"invalid-owner-prefix", func(s *Statement) { stateAt(s, 1)[freeze.OwnerOffset] = 4 }},
		{"zero-quantity-with-balanced-total", func(s *Statement) {
			setQuantity(s, 2, 0)
			setQuantity(s, 3, 1024)
		}},
		{"zero-satoshis-with-balanced-total", func(s *Statement) {
			binary.LittleEndian.PutUint64(stateAt(s, 2), 0)
			binary.LittleEndian.PutUint64(stateAt(s, 3), 3000)
		}},
		{"overflow-with-balanced-total", func(s *Statement) {
			for i, qty := range [4]uint64{math.MaxUint64, 1, math.MaxUint64 - 1, 2} {
				setQuantity(s, i, qty)
			}
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			mutant := valid
			item.edit(&mutant)
			solve(t, mutant.Assignment(), false)
		})
	}
	t.Run("old-public-inputs-with-changed-context", func(t *testing.T) {
		assignment := valid.Assignment()
		assignment.Payload[5] = valid[5] ^ 1
		solve(t, assignment, false)
	})
	t.Run("old-public-inputs-with-reordered-predecessors", func(t *testing.T) {
		mutant := valid
		copy(stateAt(&mutant, 0), stateAt(&valid, 1))
		copy(stateAt(&mutant, 1), stateAt(&valid, 0))
		assignment := mutant.Assignment()
		assignment.Public = valid.Assignment().Public
		solve(t, assignment, false)
	})
	t.Run("nonbyte-witness", func(t *testing.T) {
		assignment := valid.Assignment()
		assignment.Payload[0] = 256
		solve(t, assignment, false)
	})
}

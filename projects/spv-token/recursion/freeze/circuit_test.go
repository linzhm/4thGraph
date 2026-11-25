package freeze

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	frontendcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func controlStatements(t *testing.T) map[string]Statement {
	t.Helper()
	raw, err := os.ReadFile("testdata/script-control.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture []struct {
		Case      string `json:"case"`
		Statement string `json:"statement"`
		Digest    string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	statements := make(map[string]Statement, len(fixture))
	for _, entry := range fixture {
		encoded, err := hex.DecodeString(entry.Statement)
		if err != nil {
			t.Fatal(err)
		}
		statement, err := ParseStatement(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", statement.Digest()) != entry.Digest || hex.EncodeToString(statement.Encode()) != entry.Statement {
			t.Fatalf("%s: statement differs from the independent Script control vector", entry.Case)
		}
		statements[entry.Case] = statement
	}
	for _, name := range []string{"freeze", "unfreeze"} {
		if _, exists := statements[name]; !exists {
			t.Fatalf("missing %s Script control vector", name)
		}
	}
	return statements
}

func TestFreezeCircuitMatchesScriptControl(t *testing.T) {
	checkFreezeControl(t, 1, func(c *Circuit) frontend.Circuit { return c })
}

func TestPlainFreezeCircuitMatchesScriptControl(t *testing.T) {
	checkFreezeControl(t, 0, func(c *Circuit) frontend.Circuit { return (*PlainCircuit)(c) })
}

func checkFreezeControl(t *testing.T, expectedCommitments int, convert func(*Circuit) frontend.Circuit) {
	t.Helper()
	statements := controlStatements(t)
	started := time.Now()
	ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, convert(&Circuit{}))
	if err != nil {
		t.Fatal(err)
	}
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	if ccs.GetNbPublicVariables() != 3 || len(commitments) != expectedCommitments {
		t.Fatalf("expected two public limbs and %d commitments, got %d limbs and %d commitments",
			expectedCommitments, ccs.GetNbPublicVariables()-1, len(commitments))
	}
	t.Logf("compiled %d constraints, %d private bytes, 2 public limbs, %d commitments in %v",
		ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), len(commitments), time.Since(started))
	var options []solver.Option
	if expectedCommitments == 1 {
		if len(commitments[0].GetPublicCommitted()) != 0 {
			t.Fatal("expected zero public BSB22 indexes")
		}
		options = append(options, solver.OverrideHint(solver.GetHintID(frontendcs.Bsb22CommitmentComputePlaceholder),
			func(mod *big.Int, _ []*big.Int, out []*big.Int) error {
				value, err := rand.Int(rand.Reader, mod)
				if err == nil {
					out[0].Set(value)
				}
				return err
			}))
	}
	solve := func(t *testing.T, c *Circuit, valid bool) {
		t.Helper()
		witness, err := frontend.NewWitness(convert(c), fr.Modulus())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(witness, options...); (err == nil) != valid {
			t.Fatalf("unexpected solver result, wanted valid=%t: %v", valid, err)
		}
	}
	for _, name := range []string{"freeze", "unfreeze"} {
		t.Run(name, func(t *testing.T) {
			solve(t, statements[name].Assignment(), true)
		})
	}

	prior, successor := PairOffset, PairOffset+StateSize
	for _, mutant := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"changed-satoshis", successor, 0},
		{"changed-asset", successor + 8, 0},
		{"changed-quantity", successor + QuantityOffset, 0},
		{"changed-owner", successor + OwnerOffset, 1},
		{"changed-policy", successor + FrozenOffset + 1, 0},
		{"unchanged-flag", successor + FrozenOffset, 0},
		{"nonboolean-flag", successor + FrozenOffset, 2},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			statement := statements["freeze"]
			if statement[mutant.offset] == mutant.value {
				t.Fatal("test requires a change to the actual field")
			}
			statement[mutant.offset] = mutant.value
			// Recompute public inputs so these mutants must fail the rule.
			solve(t, statement.Assignment(), false)
		})
	}
	t.Run("zero-quantity", func(t *testing.T) {
		statement := statements["freeze"]
		clear(statement[prior+QuantityOffset : prior+OwnerOffset])
		clear(statement[successor+QuantityOffset : successor+OwnerOffset])
		solve(t, statement.Assignment(), false)
	})
	t.Run("noncanonical-owner-on-both", func(t *testing.T) {
		statement := statements["freeze"]
		statement[prior+OwnerOffset], statement[successor+OwnerOffset] = 4, 4
		solve(t, statement.Assignment(), false)
	})
	for _, replay := range []struct {
		name   string
		offset int
	}{
		{"stale-outpoint", 0},
		{"stale-paired-index", OutpointSize},
		{"stale-preimage-context", OutpointSize + IndexSize},
	} {
		t.Run(replay.name, func(t *testing.T) {
			statement := statements["freeze"]
			assignment := statement.Assignment()
			assignment.Payload[replay.offset] = statement[replay.offset] ^ 1
			solve(t, assignment, false)
		})
	}
	t.Run("out-of-range-byte", func(t *testing.T) {
		assignment := statements["freeze"].Assignment()
		assignment.Payload[0] = 256
		solve(t, assignment, false)
	})
}

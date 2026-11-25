package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/keycommit"
)

type activityFixture struct {
	Count  frontend.Variable
	Active []frontend.Variable
}

func (c *activityFixture) Define(api frontend.API) error {
	active, err := predecessorActivity(api, c.Count, len(c.Active))
	if err != nil {
		return err
	}
	for i, value := range active {
		api.AssertIsEqual(value, c.Active[i])
	}
	return nil
}

func TestPredecessorActivity(t *testing.T) {
	field := fr.Modulus()
	for _, slots := range []int{1, 2, 4} {
		ccs, err := frontend.Compile(field, r1cs.NewBuilder, &activityFixture{Active: make([]frontend.Variable, slots)})
		if err != nil {
			t.Fatal(err)
		}
		solve := func(count int, activity []frontend.Variable, accepted bool) {
			t.Helper()
			w, err := frontend.NewWitness(&activityFixture{Count: count, Active: activity}, field)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ccs.Solve(w); (err == nil) != accepted {
				t.Fatalf("slots=%d count=%d activity=%v: expected accept=%t, got %v", slots, count, activity, accepted, err)
			}
		}
		activity := make([]frontend.Variable, slots)
		for count := -1; count <= slots+1; count++ {
			for i := range activity {
				activity[i] = 0
				if i < count {
					activity[i] = 1
				}
			}
			solve(count, activity, 0 <= count && count <= slots)
		}
		activity[0] = 0
		if slots > 1 {
			solve(1, activity, false)
		}
	}
}

type predecessorProofProbe struct {
	SelfID [2]frontend.Variable `gnark:",public"`
	Count  frontend.Variable
	Key    keycommit.Key
	Prior  [][32]frontend.Variable
	Proofs []Proof
	pad    padding `gnark:"-"`
}

func (c *predecessorProofProbe) Define(api frontend.API) error {
	byteAPI, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	if err := keycommit.Assert(api, &c.Key, c.SelfID); err != nil {
		return err
	}
	active, err := predecessorActivity(api, c.Count, len(c.Proofs))
	if err != nil {
		return err
	}
	_, err = assertPredecessorProofs(api, byteAPI, &c.Key, c.pad, active, c.Prior, c.Proofs)
	return err
}

func TestPredecessorProofSlots(t *testing.T) {
	if os.Getenv("CCTP_CONTINUITY_SLOT_TEST") != "1" {
		t.Skip("set CCTP_CONTINUITY_SLOT_TEST=1 to compile the recursion-only profiles")
	}
	pad, _, err := loadPadding()
	if err != nil {
		t.Fatal(err)
	}
	nativeKey, prior := typedFixture(t)
	_, foreign := typedFixture(t)
	if foreign.digest != prior.digest {
		t.Fatal("foreign proof must use the identical public digest")
	}
	state := provingState{}
	if err := state.useKey(nativeKey); err != nil {
		t.Fatal(err)
	}
	keyID := limbs(state.keyDigest)
	for _, slots := range []int{1, 4} {
		t.Run(fmt.Sprintf("%d-slots", slots), func(t *testing.T) {
			template := &predecessorProofProbe{Key: keycommit.Placeholder(), pad: pad,
				Prior: make([][32]frontend.Variable, slots), Proofs: make([]Proof, slots)}
			for i := range template.Proofs {
				template.Proofs[i].Commitments = make([]pedersen.Commitment[G1], 1)
			}
			start := time.Now()
			ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, template)
			if err != nil {
				t.Fatal(err)
			}
			commits := ccs.GetCommitments().(constraint.Groth16Commitments)
			if len(commits) != 1 || len(commits[0].GetPublicCommitted()) != 0 {
				t.Fatal("unexpected recursion-only BSB22 layout")
			}
			t.Logf("%d predecessor slots, %d constraints, %d BSB22 commitment, compiled in %v",
				slots, ccs.GetNbConstraints(), len(commits), time.Since(start))
			assignment := func(count int) *predecessorProofProbe {
				result := &predecessorProofProbe{
					SelfID: [2]frontend.Variable{keyID[0], keyID[1]}, Count: count, Key: state.key,
					Prior: make([][32]frontend.Variable, slots), Proofs: make([]Proof, slots),
				}
				for i := range result.Prior {
					result.Proofs[i] = pad.Proof
					var digest [32]byte
					if i < count {
						digest, result.Proofs[i] = prior.digest, prior.proof
					}
					for j, value := range digest {
						result.Prior[i][j] = value
					}
				}
				return result
			}
			solve := func(witness *predecessorProofProbe, accepted bool) {
				t.Helper()
				w, challenge, err := solverWitness(witness)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ccs.Solve(w, challenge); (err == nil) != accepted {
					t.Fatalf("expected accept=%t, solver returned %v", accepted, err)
				}
			}
			solve(assignment(1), true)
			if slots == 4 {
				solve(assignment(4), true)
				wrongKey := assignment(4)
				wrongKey.Proofs[3] = foreign.proof
				solve(wrongKey, false)
				wrongDigest := assignment(1)
				wrongDigest.Prior[3][0] = 1
				solve(wrongDigest, false)
			}
		})
	}
}

func TestContinuityV1ConstraintFingerprint(t *testing.T) {
	if os.Getenv("CCTP_CONTINUITY_SLOT_TEST") != "1" {
		t.Skip("set CCTP_CONTINUITY_SLOT_TEST=1 to compare the full circuit fingerprint")
	}
	state, _, err := compile()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := state.fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	const archived = "cctp-continuity/v1 70a485af0ccc64cffb4275515fabc57d9344b5104960a7ae22e2819cbd681704\n"
	if fingerprint != archived {
		t.Fatalf("continuity v1 fingerprint changed: got %s, want %s", fingerprint, archived)
	}
	t.Logf("v1 fingerprint matches: %s", fingerprint)
}

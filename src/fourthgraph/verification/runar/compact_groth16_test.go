package codegen

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func TestCompactForthPlanRejectsMissingChecksAndChangedSchedules(t *testing.T) {
	rounds := func(naf []int) []int {
		result := slices.Clone(naf[:len(naf)-1])
		slices.Reverse(result)
		return result
	}
	formula := func(inputs int) ForthFp2Formula {
		return ForthFp2Formula{
			Steps:   []ForthFp2Step{{"square", []int{0}}, {"square", []int{1}}, {"square", []int{2}}},
			Returns: []int{inputs, inputs + 1, inputs + 2},
		}
	}
	plan := CompactForthPlan{
		Stages: []string{"prime", "curve-a", "curve-c", "curve-b", "subgroup", "pairs",
			"inverse", "miller", "fixed", "frobenius", "identity"},
		Subgroup: rounds(computeNAF(bn254SubgroupCheckScalar)), Miller: rounds(bn254SixXPlus2NAF),
		Double: formula(3), MixedAdd: formula(5),
	}
	config := Groth16Config{compactDelta: &compactLines{}, compactSubgroup: "projective-naf"}
	if err := plan.validate(config); err != nil {
		t.Fatalf("valid plan shape rejected: %v", err)
	}
	for name, mutate := range map[string]func(CompactForthPlan) CompactForthPlan{
		"missing inverse check": func(p CompactForthPlan) CompactForthPlan {
			p.Stages = slices.Delete(slices.Clone(p.Stages), 6, 7)
			return p
		},
		"missing Miller round": func(p CompactForthPlan) CompactForthPlan {
			p.Miller = p.Miller[1:]
			return p
		},
		"missing subgroup round": func(p CompactForthPlan) CompactForthPlan {
			p.Subgroup = p.Subgroup[1:]
			return p
		},
		"invalid coordinate reference": func(p CompactForthPlan) CompactForthPlan {
			p.Double.Returns = []int{3, 4, 6}
			return p
		},
	} {
		if err := mutate(plan).validate(config); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestCompactGroth16Subgroup(t *testing.T) {
	_, _, _, generator := bn254.Generators()
	var valid bn254.G2Affine
	valid.ScalarMultiplication(&generator, big.NewInt(173))
	var seed bn254.E2
	seed.A0.SetUint64(1)
	seed.A1.SetUint64(3)
	outside := bn254.MapToCurve2(&seed)
	for _, point := range []bn254.G2Affine{generator, valid, outside} {
		if !point.IsOnCurve() || point.IsInfinity() {
			t.Fatal("invalid subgroup test point")
		}
		for _, signed := range []bool{false, true} {
			var ops []StackOp
			for _, n := range []*big.Int{bn254FieldP, point.X.A0.BigInt(new(big.Int)), point.X.A1.BigInt(new(big.Int)),
				point.Y.A0.BigInt(new(big.Int)), point.Y.A1.BigInt(new(big.Int))} {
				ops = append(ops, StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: n}})
			}
			tracker := NewBN254Tracker([]string{"_q", "x0", "x1", "y0", "y1"}, func(op StackOp) {
				ops = append(ops, op)
			})
			tracker.SetQAtBottom()
			tracker.primeCacheActive = true
			emitCompactG2Subgroup(tracker, "x0", "x1", "y0", "y1", signed)
			for len(tracker.nm) != 0 {
				tracker.drop()
			}
			ops = append(ops, StackOp{Op: "push", Value: bigIntPush(1)})
			err := buildAndExecute(t, ops)
			if (err == nil) != point.IsInSubGroup() {
				t.Fatalf("subgroup result disagreed with gnark (signed = %t): %v", signed, err)
			}
		}
	}
}

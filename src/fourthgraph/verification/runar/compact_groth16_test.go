package codegen

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

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

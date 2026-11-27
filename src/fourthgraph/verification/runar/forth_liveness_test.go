package codegen

import (
	"math/big"
	"testing"
)

func TestForthFp2LastUse(t *testing.T) {
	point := compactJacobian{compactFp2{"x0", "x1"}, compactFp2{"y0", "y1"}, compactFp2{"z0", "z1"}}
	affine := []compactFp2{{"qx0", "qx1"}, {"qy0", "qy1"}}
	formula := ForthFp2Formula{
		Steps: []ForthFp2Step{
			{"multiply", []int{0, 0}}, // x squared, returned and used in the subtraction
			{"square", []int{2}},      // evaluated even though its result is discarded
			{"subtract", []int{5, 3}}, // qx stays available to the caller
			{"times-three", []int{7}},
		},
		Returns: []int{8, 5, 7},
	}
	for _, lastUse := range []bool{false, true} {
		ops := []StackOp{pushBigInt(bn254FieldP)}
		for _, n := range []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29} {
			ops = append(ops, pushInt64(n))
		}
		names := []string{"_q", "x0", "x1", "y0", "y1", "z0", "z1", "qx0", "qx1", "qy0", "qy1"}
		tracker := NewBN254Tracker(names, func(op StackOp) { ops = append(ops, op) })
		tracker.SetQAtBottom()
		tracker.primeCacheActive = true
		tracker.modThreshold = 64
		plan := CompactForthPlan{JacobianLastUse: lastUse}
		plan.emitJacobian(formula, tracker, point, affine...)
		if len(tracker.nm) != len(names) {
			t.Fatalf("lastUse=%t, unexpected live slots: %v", lastUse, tracker.nm)
		}
		want := []int64{-66, -21, -5, 12, -22, -7, 17, 19, 23, 29}
		for i, name := range names[1:] {
			const result = "_test_formula_output"
			bn254FieldMod(tracker, name, result)
			tracker.pushBigInt("_test_expected", new(big.Int).Mod(big.NewInt(want[i]), bn254FieldP))
			tracker.rawBlock([]string{result, "_test_expected"}, "", func(emit func(StackOp)) {
				emit(opcode("OP_NUMEQUALVERIFY"))
			})
		}
		tracker.drop() // _q
		ops = append(ops, pushInt64(1))
		if err := buildAndExecute(t, ops); err != nil {
			t.Fatalf("lastUse=%t, formula result: %v", lastUse, err)
		}
	}
}

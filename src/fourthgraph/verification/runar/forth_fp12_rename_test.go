package codegen

import (
	"slices"
	"testing"
)

func TestForthFp12InPlaceRename(t *testing.T) {
	a := appendFp12SlotNames([]string{"_q"}, "before")
	b := appendFp12SlotNames([]string{"_q"}, "after")
	// A still-live caller value splits the Fp12 coefficients.
	a = slices.Insert(a, 5, "caller")
	b = slices.Insert(b, 5, "caller")
	var ops []StackOp
	tracker := NewBN254Tracker(a, func(op StackOp) { ops = append(ops, op) })
	tracker.fp12RenameInPlace = true
	bn254Fp12RenamePrefix(tracker, "before", "after")
	if len(ops) != 0 || !slices.Equal(tracker.nm, b) {
		t.Fatalf("rename emitted %d ops and left %v, want %v", len(ops), tracker.nm, b)
	}
}

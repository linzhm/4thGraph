// Lowers the fixed-statement verifier stages emitted by the Forth compiler.
package codegen

import (
	"fmt"
	"slices"
)

// CompactForthPlan holds the ordered verification phases and signed schedules
// from the Forth source. Both ladders start at the point for the leading 1.
type CompactForthPlan struct {
	Stages   []string
	Subgroup []int
	Miller   []int
	Double   ForthFp2Formula
	MixedAdd ForthFp2Formula
}

// A Forth layout permutes references at build time. Each step below is a
// field operation on an input or the result of a previous step.
type ForthFp2Formula struct {
	Steps   []ForthFp2Step
	Returns []int
}

type ForthFp2Step struct {
	Op   string
	Args []int
}

var forthFp2Scale = map[string]int64{
	"times-two": 2, "times-three": 3, "times-four": 4, "times-eight": 8,
}

func (f ForthFp2Formula) validate(inputs int) bool {
	for i, step := range f.Steps {
		arity := 1
		switch step.Op {
		case "multiply", "subtract":
			arity = 2
		case "square":
		default:
			if forthFp2Scale[step.Op] == 0 {
				return false
			}
		}
		if len(step.Args) != arity {
			return false
		}
		for _, arg := range step.Args {
			if arg < 0 || arg >= inputs+i {
				return false
			}
		}
	}
	if len(f.Returns) != 3 {
		return false
	}
	for i, slot := range f.Returns {
		if slot < inputs || slot >= inputs+len(f.Steps) || slices.Contains(f.Returns[:i], slot) {
			return false
		}
	}
	return true
}

func (f ForthFp2Formula) emit(t *BN254Tracker, p compactJacobian, affine ...compactFp2) {
	values := append([]compactFp2{p.x, p.y, p.z}, affine...)
	s := compactStep{t: t}
	for _, step := range f.Steps {
		a := values[step.Args[0]]
		var result compactFp2
		switch step.Op {
		case "multiply":
			result = s.mul(a, values[step.Args[1]])
		case "subtract":
			result = s.sub(a, values[step.Args[1]])
		case "square":
			result = s.square(a)
		default:
			result = s.scale(a, forthFp2Scale[step.Op])
		}
		values = append(values, result)
	}
	s.finish(p, compactJacobian{values[f.Returns[0]], values[f.Returns[1]], values[f.Returns[2]]})
}

func nafFromForth(rounds []int) []int {
	naf := make([]int, len(rounds)+1)
	for i, digit := range rounds {
		naf[len(rounds)-i-1] = digit
	}
	naf[len(rounds)] = 1
	return naf
}

func (p CompactForthPlan) validate(config Groth16Config) error {
	if config.compactDelta == nil || config.compactSubgroup != "projective-naf" {
		return fmt.Errorf("Forth verifier requires the compact fixed statement and NAF subgroup layout")
	}
	// The typed source enforces this order. Check it at the adapter boundary
	// too so a standalone caller cannot omit a required consensus check.
	required := []string{"prime", "curve-a", "curve-c", "curve-b", "subgroup", "pairs",
		"inverse", "miller", "fixed", "frobenius", "identity"}
	if !slices.Equal(p.Stages, required) {
		return fmt.Errorf("Forth verifier has missing or misordered verification stages")
	}
	if !slices.Equal(nafFromForth(p.Subgroup), computeNAF(bn254SubgroupCheckScalar)) {
		return fmt.Errorf("Forth subgroup digits must encode the fixed 6*u^2 NAF")
	}
	if !slices.Equal(nafFromForth(p.Miller), bn254SixXPlus2NAF) {
		return fmt.Errorf("Forth Miller digits must match the 6*u+2 witness schedule")
	}
	if !p.Double.validate(3) || !p.MixedAdd.validate(5) {
		return fmt.Errorf("invalid Forth Jacobian coordinate formula")
	}
	return nil
}

func forthWitnessSlots(rounds []int) []string {
	names := []string{"_q"}
	for i, digit := range rounds {
		suffix := itoa(i)
		names = append(names, "_wlam_d1_"+suffix+"_0", "_wlam_d1_"+suffix+"_1")
		if digit != 0 {
			names = append(names, "_wlam_a1_"+suffix+"_0", "_wlam_a1_"+suffix+"_1")
		}
	}
	names = appendFp12SlotNames(names, waResidueC)
	names = appendFp12SlotNames(names, waResidueCInv)
	return append(names, waResidueSel, "proof_ax", "proof_ay", "proof_bx0", "proof_bx1",
		"proof_by0", "proof_by1", "proof_cx", "proof_cy")
}

func forthRequirePrime(t *BN254Tracker, threshold int) {
	t.copyToTop("_q", "_q_check")
	t.pushBigInt("_q_expected", bn254FieldP)
	t.rawBlock([]string{"_q_check", "_q_expected"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
	t.SetQAtBottom()
	t.primeCacheActive = true
	t.modThreshold = threshold
}

func forthBindPairs(t *BN254Tracker) {
	for _, bind := range [][2]string{
		{"proof_ax", "p1x"}, {"proof_ay", "p1y"},
		{"proof_bx0", "q1x0"}, {"proof_bx1", "q1x1"},
		{"proof_by0", "q1y0"}, {"proof_by1", "q1y1"},
		{"proof_cx", "p3x"}, {"proof_cy", "p3y"},
	} {
		t.toTop(bind[0])
		t.rename(bind[1])
	}
}

func forthRequireIdentity(t *BN254Tracker) {
	bn254Fp12IsOne(t, "_f", "_final_check")
	t.toTop("_final_check")
	t.rawBlock([]string{"_final_check"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})
}

// EmitCompactForthVerifier emits a complete predicate from the checked
// source plan. Field arithmetic and named-stack operations are backend words.
func EmitCompactForthVerifier(emit func(StackOp), config Groth16Config, plan CompactForthPlan) error {
	if err := plan.validate(config); err != nil {
		return err
	}
	t := NewBN254Tracker(forthWitnessSlots(plan.Miller), emit)
	for _, stage := range plan.Stages {
		switch stage {
		case "prime":
			forthRequirePrime(t, config.ModuloThreshold)
		case "curve-a":
			emitWAG1OnCurveCheck(t, "proof_ax", "proof_ay")
		case "curve-c":
			emitWAG1OnCurveCheck(t, "proof_cx", "proof_cy")
		case "curve-b":
			emitWAG2OnCurveCheck(t, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1")
		case "subgroup":
			emitCompactG2Digits(t, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1", true, nafFromForth(plan.Subgroup),
				func(t *BN254Tracker, p compactJacobian) { plan.Double.emit(t, p) },
				func(t *BN254Tracker, p compactJacobian, x, y compactFp2) { plan.MixedAdd.emit(t, p, x, y) })
		case "pairs":
			forthBindPairs(t)
		case "inverse":
			emitWAResidueInverseCheck(t)
		case "miller":
			emitWAMillerLoop(t, config.compactDelta, plan.Miller)
		case "fixed":
			emitWASelectScaledAlphaNegBeta(t, config, "_ab")
			bn254Fp12Mul(t, "_f", "_ab", "_f_with_ab")
			bn254Fp12RenamePrefix(t, "_f_with_ab", "_f")
		case "frobenius":
			emitWAResidueFrobeniusTerms(t)
		case "identity":
			forthRequireIdentity(t)
		}
	}
	for len(t.nm) > 0 {
		t.drop()
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(1)})
	return nil
}

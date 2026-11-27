// Fixed-statement Groth16 lowering for the pinned Rúnar code generator.
package codegen

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type compactLine struct {
	negSlope, intercept bn254.E2
}

type compactLines struct {
	double, add []compactLine
	correction  [2]compactLine
}

func compactE2(limbs [2]*big.Int) (value bn254.E2) {
	value.A0.SetBigInt(limbs[0])
	value.A1.SetBigInt(limbs[1])
	return value
}

// These are the same Py-scaled affine lines used by the witness builder.
// Keep their exact representatives because the residue proof uses the raw
// Miller product, including its scalings before final exponentiation.
func compactFixedLines(coords [4]*big.Int) (compactLines, error) {
	base := bn254.G2Affine{
		X: compactE2([2]*big.Int{coords[0], coords[1]}),
		Y: compactE2([2]*big.Int{coords[2], coords[3]}),
	}
	if base.IsInfinity() || !base.IsOnCurve() || !base.IsInSubGroup() {
		return compactLines{}, fmt.Errorf("invalid fixed Groth16 G2 point")
	}
	var negBase bn254.G2Affine
	negBase.Neg(&base)
	point := base
	line := func(other *bn254.G2Affine) compactLine {
		var num, den, lambda, intercept bn254.E2
		if other == nil {
			num.Square(&point.X)
			three := num
			num.Double(&num).Add(&num, &three)
			den.Double(&point.Y)
		} else {
			num.Sub(&other.Y, &point.Y)
			den.Sub(&other.X, &point.X)
		}
		// Use the legacy affine update and inverse convention, including in
		// the final two Frobenius corrections.
		lambda.Inverse(&den).Mul(&lambda, &num)
		intercept.Mul(&lambda, &point.X).Sub(&intercept, &point.Y)
		x := point.X
		if other != nil {
			x = other.X
		}
		var next bn254.G2Affine
		next.X.Square(&lambda).Sub(&next.X, &point.X).Sub(&next.X, &x)
		next.Y.Sub(&point.X, &next.X).Mul(&next.Y, &lambda).Sub(&next.Y, &point.Y)
		point = next
		lambda.Neg(&lambda)
		return compactLine{lambda, intercept}
	}
	var lines compactLines
	for i := len(bn254SixXPlus2NAF) - 2; i >= 0; i-- {
		lines.double = append(lines.double, line(nil))
		switch bn254SixXPlus2NAF[i] {
		case 1:
			lines.add = append(lines.add, line(&base))
		case -1:
			lines.add = append(lines.add, line(&negBase))
		}
	}
	x1, y1 := compactE2(bn254Gamma12), compactE2(bn254Gamma13)
	x2, y2 := compactE2(bn254Gamma12Sq), compactE2(bn254Gamma13Sq)
	var q1, q2 bn254.G2Affine
	q1.X.Conjugate(&base.X).Mul(&q1.X, &x1)
	q1.Y.Conjugate(&base.Y).Mul(&q1.Y, &y1)
	q2.X.Mul(&base.X, &x2)
	q2.Y.Mul(&base.Y, &y2).Neg(&q2.Y)
	lines.correction[0] = line(&q1)
	lines.correction[1] = line(&q2)
	return lines, nil
}

func compactMillerProduct(lines compactLines, point bn254.G1Affine) bn254.E12 {
	var f bn254.E12
	f.SetOne()
	mulLine := func(line compactLine) {
		var sparse bn254.E12
		sparse.C0.B0.A0 = point.Y
		sparse.C1.B0.A0.Mul(&line.negSlope.A0, &point.X)
		sparse.C1.B0.A1.Mul(&line.negSlope.A1, &point.X)
		sparse.C1.B1 = line.intercept
		f.Mul(&f, &sparse)
	}
	add := 0
	for i, line := range lines.double {
		f.Square(&f)
		mulLine(line)
		if bn254SixXPlus2NAF[len(lines.double)-1-i] != 0 {
			mulLine(lines.add[add])
			add++
		}
	}
	for _, line := range lines.correction {
		mulLine(line)
	}
	return f
}

// ConfigureCompactGroth16 specializes a standalone verifier for its entire
// public statement. It folds e(L,-gamma) into the alpha/beta residue factor.
func ConfigureCompactGroth16(config *Groth16Config, subgroup string) error {
	switch subgroup {
	case "affine", "projective-binary", "projective-naf":
	default:
		return fmt.Errorf("unsupported compact subgroup schedule %q", subgroup)
	}
	for _, input := range config.PinnedPublicInputs {
		if input == nil {
			return fmt.Errorf("compact Groth16 requires all public inputs to be pinned")
		}
	}
	point := groth16MSMPoint(*config)
	if point.IsInfinity() || !point.IsOnCurve() {
		return fmt.Errorf("invalid folded Groth16 G1 point")
	}
	gamma, err := compactFixedLines(config.GammaNegG2)
	if err != nil {
		return err
	}
	delta, err := compactFixedLines(config.DeltaNegG2)
	if err != nil {
		return err
	}
	fixed := compactMillerProduct(gamma, point)
	alphaBeta := bn254FlatToE12(config.AlphaNegBetaFp12)
	fixed.Mul(&fixed, &alphaBeta)
	config.AlphaNegBetaFp12 = bn254E12ToFlat(&fixed)
	config.compactDelta = &delta
	config.compactSubgroup = subgroup
	return nil
}

func emitCompactDelta(t *BN254Tracker, line compactLine) {
	t.copyToTop("p3y", "_compact_line_c0_0")
	t.pushBigInt("_compact_line_c0_1", big.NewInt(0))
	for i, scalar := range []*big.Int{line.negSlope.A0.BigInt(new(big.Int)), line.negSlope.A1.BigInt(new(big.Int))} {
		t.copyToTop("p3x", "_compact_px")
		t.pushBigInt("_compact_slope", scalar)
		bn254FieldMul(t, "_compact_px", "_compact_slope", "_compact_line_c3_"+itoa(i))
	}
	t.pushBigInt("_compact_line_c4_0", line.intercept.A0.BigInt(new(big.Int)))
	t.pushBigInt("_compact_line_c4_1", line.intercept.A1.BigInt(new(big.Int)))
	bn254Fp12MulSparse(t, "_f", "_compact_line", "_compact_product")
	bn254Fp12RenamePrefix(t, "_compact_product", "_f")
}

type compactFp2 [2]string

type compactJacobian struct {
	x, y, z compactFp2
}

// Arithmetic temporaries are scoped to one group operation so the tracker
// never carries the chain of intermediate Jacobian points across rounds.
type compactStep struct {
	t     *BN254Tracker
	temps []compactFp2
}

func (s *compactStep) next() compactFp2 {
	name := "_compact_j" + itoa(len(s.temps))
	pair := compactFp2{name + "_0", name + "_1"}
	s.temps = append(s.temps, pair)
	return pair
}

func (s *compactStep) binary(op func(*BN254Tracker, string, string, string, string, string, string), a, b compactFp2) compactFp2 {
	r := s.next()
	s.t.copyToTop(a[0], "_compact_a0")
	s.t.copyToTop(a[1], "_compact_a1")
	s.t.copyToTop(b[0], "_compact_b0")
	s.t.copyToTop(b[1], "_compact_b1")
	op(s.t, "_compact_a0", "_compact_a1", "_compact_b0", "_compact_b1", r[0], r[1])
	return r
}

func (s *compactStep) add(a, b compactFp2) compactFp2 { return s.binary(bn254Fp2Add, a, b) }
func (s *compactStep) sub(a, b compactFp2) compactFp2 { return s.binary(bn254Fp2Sub, a, b) }
func (s *compactStep) mul(a, b compactFp2) compactFp2 { return s.binary(bn254Fp2Mul, a, b) }

func (s *compactStep) square(a compactFp2) compactFp2 {
	r := s.next()
	s.t.copyToTop(a[0], "_compact_a0")
	s.t.copyToTop(a[1], "_compact_a1")
	bn254Fp2Sqr(s.t, "_compact_a0", "_compact_a1", r[0], r[1])
	return r
}

func (s *compactStep) scale(a compactFp2, scalar int64) compactFp2 {
	r := s.next()
	for i, name := range a {
		s.t.copyToTop(name, "_compact_scale")
		bn254FieldMulConst(s.t, "_compact_scale", scalar, r[i])
	}
	return r
}

func (s *compactStep) drop(a compactFp2) {
	bn254DropNames(s.t, a[:])
}

func (s *compactStep) finish(before, after compactJacobian) {
	for _, old := range []compactFp2{before.x, before.y, before.z} {
		s.drop(old)
	}
	for _, pair := range s.temps {
		if pair != after.x && pair != after.y && pair != after.z {
			s.drop(pair)
		}
	}
	for _, pair := range [][2]compactFp2{{after.x, before.x}, {after.y, before.y}, {after.z, before.z}} {
		for i, name := range pair[0] {
			s.t.toTop(name)
			s.t.rename(pair[1][i])
		}
	}
}

func compactDouble(t *BN254Tracker, p compactJacobian) {
	s := compactStep{t: t}
	yy := s.square(p.y)
	m := s.scale(s.square(p.x), 3)
	d := s.scale(s.mul(p.x, yy), 4)
	x := s.sub(s.square(m), s.scale(d, 2))
	y := s.sub(s.mul(m, s.sub(d, x)), s.scale(s.square(yy), 8))
	z := s.scale(s.mul(p.y, p.z), 2)
	s.finish(p, compactJacobian{x, y, z})
}

func compactAddMixed(t *BN254Tracker, p compactJacobian, x, y compactFp2) {
	s := compactStep{t: t}
	zz := s.square(p.z)
	h := s.sub(s.mul(x, zz), p.x)
	m := s.sub(s.mul(y, s.mul(zz, p.z)), p.y)
	hh := s.square(h)
	hhh, v := s.mul(h, hh), s.mul(p.x, hh)
	rx := s.sub(s.sub(s.square(m), hhh), s.scale(v, 2))
	ry := s.sub(s.mul(m, s.sub(v, rx)), s.mul(p.y, hhh))
	rz := s.mul(p.z, h)
	s.finish(p, compactJacobian{rx, ry, rz})
}

func emitCompactG2Subgroup(t *BN254Tracker, x0, x1, y0, y1 string, signed bool) {
	x, y := compactFp2{x0, x1}, compactFp2{y0, y1}
	p := compactJacobian{compactFp2{"_cg2x0", "_cg2x1"}, compactFp2{"_cg2y0", "_cg2y1"}, compactFp2{"_cg2z0", "_cg2z1"}}
	for i := range x {
		t.copyToTop(x[i], p.x[i])
		t.copyToTop(y[i], p.y[i])
		t.pushBigInt(p.z[i], big.NewInt(int64(1-i)))
	}
	// The same [6u²] ladder as the affine check, with Z=1 at input.
	// If a denominator degenerates Z becomes zero and stays zero. A
	// prime-order point cannot hit those exceptions at these scalar prefixes.
	digits := make([]int, bn254SubgroupCheckScalar.BitLen())
	for i := range digits {
		digits[i] = int(bn254SubgroupCheckScalar.Bit(i))
	}
	negY := compactFp2{"_cg2ny0", "_cg2ny1"}
	if signed {
		digits = computeNAF(bn254SubgroupCheckScalar)
		for i, name := range y {
			t.copyToTop(name, "_cg2_neg")
			bn254FieldNeg(t, "_cg2_neg", negY[i])
		}
	}
	for i := len(digits) - 2; i >= 0; i-- {
		compactDouble(t, p)
		switch digits[i] {
		case 1:
			compactAddMixed(t, p, x, y)
		case -1:
			compactAddMixed(t, p, x, negY)
		}
	}
	if signed {
		bn254DropNames(t, negY[:])
	}
	for i, name := range p.z {
		t.copyToTop(name, "_cz")
		bn254FieldMod(t, "_cz", "_cz"+itoa(i))
	}
	t.rawBlock([]string{"_cz0", "_cz1"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLOR"})
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})
	for i := range x {
		t.copyToTop(x[i], "_cpsi_x_"+itoa(i))
		t.copyToTop(y[i], "_cpsi_y_"+itoa(i))
	}
	bn254G2FrobeniusP(t, "_cpsi", "_cpsi_out")
	s := compactStep{t: t}
	zz := s.square(p.z)
	dx := s.sub(p.x, s.mul(compactFp2{"_cpsi_out_x_0", "_cpsi_out_x_1"}, zz))
	dy := s.sub(p.y, s.mul(compactFp2{"_cpsi_out_y_0", "_cpsi_out_y_1"}, s.mul(zz, p.z)))
	for _, pair := range []compactFp2{dx, dy} {
		for _, name := range pair {
			bn254FieldMod(t, name, "_cdiff")
			t.rawBlock([]string{"_cdiff"}, "", func(e func(StackOp)) {
				e(StackOp{Op: "push", Value: bigIntPush(0)})
				e(StackOp{Op: "opcode", Code: "OP_NUMEQUALVERIFY"})
			})
		}
	}
	for _, pair := range s.temps {
		if pair != dx && pair != dy {
			s.drop(pair)
		}
	}
	for _, pair := range []compactFp2{p.x, p.y, p.z, {"_cpsi_out_x_0", "_cpsi_out_x_1"}, {"_cpsi_out_y_0", "_cpsi_out_y_1"}} {
		s.drop(pair)
	}
}

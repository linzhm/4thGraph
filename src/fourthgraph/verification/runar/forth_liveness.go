package codegen

// emitJacobian selects the operand schedule for a checked Forth formula.
func (p CompactForthPlan) emitJacobian(f ForthFp2Formula, t *BN254Tracker, point compactJacobian, affine ...compactFp2) {
	if p.JacobianLastUse {
		f.emitLastUse(t, point, affine...)
	} else {
		f.emit(t, point, affine...)
	}
}

func (f ForthFp2Formula) emitLastUse(t *BN254Tracker, point compactJacobian, affine ...compactFp2) {
	coordinates := []compactFp2{point.x, point.y, point.z}
	values := append(coordinates, affine...)
	inputs := len(values)
	uses := make([]int, inputs+len(f.Steps))
	for _, step := range f.Steps {
		for _, slot := range step.Args {
			uses[slot]++
		}
	}
	for _, slot := range f.Returns {
		uses[slot]++
	}
	for slot, pair := range coordinates {
		if uses[slot] == 0 {
			bn254DropNames(t, pair[:])
		}
	}

	for index, step := range f.Steps {
		name := "_forth_result_" + itoa(index)
		result := compactFp2{name + "_0", name + "_1"}
		var args [2]compactFp2
		for i, slot := range step.Args {
			uses[slot]--
			value := values[slot]
			// The affine point is shared by the subgroup ladder. A value
			// used later in this step (including a repeated operand) or
			// returned by the formula also needs to stay in its slot.
			if uses[slot] > 0 || (slot >= len(coordinates) && slot < inputs) {
				copyName := "_forth_arg_" + itoa(i)
				args[i] = compactFp2{copyName + "_0", copyName + "_1"}
				for component, source := range value {
					t.copyToTop(source, args[i][component])
				}
			} else {
				args[i] = value
			}
		}
		a, b := args[0], args[1]
		switch step.Op {
		case "multiply":
			bn254Fp2Mul(t, a[0], a[1], b[0], b[1], result[0], result[1])
		case "subtract":
			bn254Fp2Sub(t, a[0], a[1], b[0], b[1], result[0], result[1])
		case "square":
			bn254Fp2Sqr(t, a[0], a[1], result[0], result[1])
		default:
			for i, component := range a {
				bn254FieldMulConst(t, component, forthFp2Scale[step.Op], result[i])
			}
		}
		values = append(values, result)
		if uses[inputs+index] == 0 {
			bn254DropNames(t, result[:])
		}
	}
	// The next operation locates coordinates by name. Rebind them at
	// their existing stack indices without moving them to the top.
	for i, slot := range f.Returns {
		for component, name := range values[slot] {
			t.nm[len(t.nm)-1-t.findDepth(name)] = coordinates[i][component]
		}
	}
}

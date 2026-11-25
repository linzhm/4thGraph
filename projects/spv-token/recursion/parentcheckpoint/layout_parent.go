package parentcheckpoint

import (
	"fmt"
	"math/bits"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/freeze"
)

// ParentOutputLayout is one compile-time wire layout and its eligible vouts.
type ParentOutputLayout struct {
	Layout        FixedParentLayout
	EligibleVouts []int
}

// BoundParentCase exposes the layout-specific wire fields. The application
// must gate reads from Context with Selector, which is one only for the
// authenticated case. The inactive slices are views into the same raw buffer.
type BoundParentCase struct {
	Selector        frontend.Variable
	Context         BoundParentContext
	EligibleOutputs []BoundParentSlot
}

// BoundParentSlot preserves the exact width of an eligible output. Selector
// is one only when this layout and vout are selected. Gate slot-specific
// assertions with Selector.
type BoundParentSlot struct {
	Vout     int
	Selector frontend.Variable
	Satoshis frontend.Variable
	TxOut    []frontend.Variable
	Script   []frontend.Variable
}

type BoundParentTransaction struct {
	Vout    frontend.Variable
	Layouts []BoundParentCase
}

type BoundLayoutParentOutput struct {
	Vout, Satoshis frontend.Variable
	TxOut, Script  []frontend.Variable
	Layouts        []BoundParentCase
}

type parentLayoutSet struct {
	fields []fixedParentFields
	width  int
}

// MaxParentSerializedSize returns the private buffer width required by BindParentTransaction.
func MaxParentSerializedSize(layouts []ParentOutputLayout) (int, error) {
	set, err := inspectParentLayouts(layouts)
	return set.width, err
}

func inspectParentLayouts(layouts []ParentOutputLayout) (parentLayoutSet, error) {
	var set parentLayoutSet
	if len(layouts) == 0 {
		return set, fmt.Errorf("expected at least one parent layout")
	}
	set.fields = make([]fixedParentFields, len(layouts))
	for i, option := range layouts {
		for _, previous := range layouts[:i] {
			if slices.Equal(option.Layout.InputScriptLengths, previous.Layout.InputScriptLengths) &&
				slices.Equal(option.Layout.OutputScriptLengths, previous.Layout.OutputScriptLengths) {
				return set, fmt.Errorf("duplicate parent wire layout at index %d", i)
			}
		}
		fields, err := option.Layout.fields()
		if err != nil {
			return set, fmt.Errorf("parent layout %d: %w", i, err)
		}
		if err := validateEligibleVouts(fields, option.EligibleVouts); err != nil {
			return set, fmt.Errorf("parent layout %d: %w", i, err)
		}
		set.width = max(set.width, fields.width)
		set.fields[i] = fields
	}
	return set, nil
}

// BindParentOutput authenticates the parent and selects one output of a common
// shape across all layouts. For eligible outputs of different shapes, use
// BindParentTransaction and its individually gated output views.
func BindParentOutput(api frontend.API, raw, actualOutpoint []frontend.Variable,
	layoutIndex frontend.Variable, layouts []ParentOutputLayout) (BoundLayoutParentOutput, error) {
	var selected BoundLayoutParentOutput
	set, err := inspectParentLayouts(layouts)
	if err != nil {
		return selected, err
	}
	shape := set.fields[0].outputs[layouts[0].EligibleVouts[0]]
	for i, layout := range layouts {
		for _, slot := range layout.EligibleVouts {
			if !sameParentOutputShape(shape, set.fields[i].outputs[slot]) {
				return selected, fmt.Errorf("eligible vouts must share one TxOut shape across layouts")
			}
		}
	}
	parent, err := bindParentTransaction(api, raw, actualOutpoint, layoutIndex, layouts, set)
	if err != nil {
		return selected, err
	}
	selected.Vout, selected.Layouts = parent.Vout, parent.Layouts
	selected.TxOut = make([]frontend.Variable, shape.end-shape.start)
	for i := range selected.TxOut {
		selected.TxOut[i] = 0
	}
	for _, layout := range parent.Layouts {
		for _, output := range layout.EligibleOutputs {
			for i, value := range output.TxOut {
				selected.TxOut[i] = api.Add(selected.TxOut[i], api.Mul(output.Selector, value))
			}
		}
	}
	selected.Script = selected.TxOut[shape.script-shape.start:]
	selected.Satoshis = parentUint64(api, selected.TxOut[:8])
	return selected, nil
}

// BindParentTransaction authenticates one exact canonical wire parent from a finite
// layout list. LayoutIndex is a constrained zero-based selector. Raw is the
// complete signed parent followed by zero bytes up to MaxParentSerializedSize.
// Exactly one eligible slot across the layouts has a selector of one.
// The caller must derive actualOutpoint from authenticated child context and
// validate the selected output policy and the predecessor's authorization.
func BindParentTransaction(api frontend.API, raw, actualOutpoint []frontend.Variable,
	layoutIndex frontend.Variable, layouts []ParentOutputLayout) (BoundParentTransaction, error) {
	set, err := inspectParentLayouts(layouts)
	if err != nil {
		return BoundParentTransaction{}, err
	}
	return bindParentTransaction(api, raw, actualOutpoint, layoutIndex, layouts, set)
}

func bindParentTransaction(api frontend.API, raw, actualOutpoint []frontend.Variable,
	layoutIndex frontend.Variable, layouts []ParentOutputLayout, set parentLayoutSet) (BoundParentTransaction, error) {
	var selected BoundParentTransaction
	if len(raw) != set.width || len(actualOutpoint) != 36 {
		return selected, fmt.Errorf("expected %d raw buffer bytes and a 36-byte outpoint", set.width)
	}
	for _, value := range actualOutpoint[32:] {
		api.ToBinary(value, 8)
	}
	selected.Vout = parentUint64(api, actualOutpoint[32:])
	selected.Layouts = make([]BoundParentCase, len(layouts))
	selectors := make([]frontend.Variable, len(layouts))
	widths := make([]int, len(layouts))
	var voutCount frontend.Variable = 0
	const maxMoney = 21_000_000 * 100_000_000
	for i, fields := range set.fields {
		active := api.IsZero(api.Sub(layoutIndex, i))
		selectors[i], widths[i] = active, fields.width
		parentCase := BoundParentCase{
			Selector: active, Context: parentContext(raw, fields),
			EligibleOutputs: make([]BoundParentSlot, len(layouts[i].EligibleVouts)),
		}
		for _, compact := range fields.compact {
			for j, value := range compact.bytes {
				api.AssertIsEqual(api.Mul(active, api.Sub(raw[compact.offset+j], value)), 0)
			}
		}
		amounts := make([]frontend.Variable, len(fields.outputs))
		for j, output := range fields.outputs {
			amounts[j] = parentUint64(api, raw[output.start:output.start+8])
			api.ToBinary(api.Mul(active, api.Sub(maxMoney, amounts[j])), bits.Len64(maxMoney))
		}
		for j, slot := range layouts[i].EligibleVouts {
			matches := api.Mul(active, api.IsZero(api.Sub(selected.Vout, slot)))
			voutCount = api.Add(voutCount, matches)
			field := fields.outputs[slot]
			parentCase.EligibleOutputs[j] = BoundParentSlot{
				Vout: slot, Selector: matches, Satoshis: amounts[slot],
				TxOut: parentCase.Context.TxOuts[slot], Script: raw[field.script:field.end],
			}
		}
		selected.Layouts[i] = parentCase
	}
	api.AssertIsEqual(voutCount, 1)
	digest, err := freeze.SHA256dAtSelectedLength(api, raw, widths, selectors)
	if err != nil {
		return selected, err
	}
	for i, value := range digest {
		api.AssertIsEqual(value, actualOutpoint[i])
	}
	return selected, nil
}

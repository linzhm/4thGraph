package parentcheckpoint

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
)

// FixedParentLayout fixes both ordered script length vectors at compile time.
// The serialized parent includes all scriptSig bytes and exactly one locktime.
type FixedParentLayout struct {
	InputScriptLengths  []int
	OutputScriptLengths []int
}

// BoundParentOutput is the selected actual output of the hashed parent. Bytes
// in TxOut and Script are in wire order. Satoshis and Quantity are decoded LE.
type BoundParentOutput struct {
	Vout     frontend.Variable
	TxOut    []frontend.Variable
	Script   []frontend.Variable
	Satoshis frontend.Variable
	Quantity frontend.Variable
	Parent   BoundParentContext
}

// BoundParentContext exposes the ordered fields of the very same transaction
// as the selected TxOut for reconstructing the predecessor's statement.
type BoundParentContext struct {
	Version, Outputs, Locktime []frontend.Variable
	Inputs                     []BoundParentInput
}

type BoundParentInput struct {
	Outpoint, ScriptSig, Sequence []frontend.Variable
}

type compactField struct {
	offset int
	bytes  []byte
}

type txOutField struct {
	start, script, end int
}

type txInField struct {
	start, script, sequence int
}

type fixedParentFields struct {
	width   int
	compact []compactField
	inputs  []txInField
	outputs []txOutField
}

// SerializedSize is the exact number of transaction bytes before SHA padding.
func (layout FixedParentLayout) SerializedSize() (int, error) {
	fields, err := layout.fields()
	return fields.width, err
}

// BindFixedParentOutput hashes the exact serialized parent provided to the
// parser and checks its SHA256d against actualOutpoint's 32 wire-order txid
// bytes. The next four little-endian bytes select one of eligibleVouts.
// Eligible outputs have an equal serialized width and carry an eight-byte LE
// quantity at quantityOffsetInScript. The caller supplies the outpoint from
// authenticated child context and enforces the selected token lock policy.
func BindFixedParentOutput(api frontend.API, raw, actualOutpoint []frontend.Variable,
	layout FixedParentLayout, eligibleVouts []int, quantityOffsetInScript int) (BoundParentOutput, error) {
	var selected BoundParentOutput
	fields, err := layout.fields()
	if err != nil {
		return selected, err
	}
	if len(raw) != fields.width || len(actualOutpoint) != 36 {
		return selected, fmt.Errorf("expected %d raw parent bytes and a 36-byte outpoint", fields.width)
	}
	if len(eligibleVouts) == 0 || quantityOffsetInScript < 0 {
		return selected, fmt.Errorf("expected at least one eligible vout and a valid token quantity offset")
	}
	previous := -1
	var selectedShape txOutField
	for i, slot := range eligibleVouts {
		if slot <= previous || slot >= len(fields.outputs) {
			return selected, fmt.Errorf("eligible vouts must be strictly increasing and in range")
		}
		previous = slot
		field := fields.outputs[slot]
		if i == 0 {
			selectedShape = field
		}
		if field.end-field.script < 8 || quantityOffsetInScript > field.end-field.script-8 ||
			field.script-field.start != selectedShape.script-selectedShape.start ||
			field.end-field.start != selectedShape.end-selectedShape.start {
			return selected, fmt.Errorf("eligible vouts must contain the quantity and share one TxOut shape")
		}
	}

	for _, compact := range fields.compact {
		for i, value := range compact.bytes {
			api.AssertIsEqual(raw[compact.offset+i], value)
		}
	}
	const maxMoney = 21_000_000 * 100_000_000
	for _, output := range fields.outputs {
		amount := parentUint64(api, raw[output.start:output.start+8])
		api.ToBinary(api.Sub(maxMoney, amount), bits.Len64(maxMoney))
	}
	for i, value := range freeze.SHA256dBytes(api, raw) {
		api.AssertIsEqual(value, actualOutpoint[i])
	}
	for _, value := range actualOutpoint[32:] {
		api.ToBinary(value, 8)
	}
	selected.Vout = parentUint64(api, actualOutpoint[32:])
	if len(eligibleVouts) == 1 {
		api.AssertIsEqual(selected.Vout, eligibleVouts[0])
		selected.TxOut = raw[selectedShape.start:selectedShape.end]
	} else {
		selectors := make([]frontend.Variable, len(eligibleVouts))
		var count frontend.Variable = 0
		for i, slot := range eligibleVouts {
			selectors[i] = api.IsZero(api.Sub(selected.Vout, slot))
			count = api.Add(count, selectors[i])
		}
		api.AssertIsEqual(count, 1)
		selected.TxOut = make([]frontend.Variable, selectedShape.end-selectedShape.start)
		for fieldByte := range selected.TxOut {
			var value frontend.Variable = 0
			for i, slot := range eligibleVouts {
				value = api.Add(value, api.Mul(selectors[i], raw[fields.outputs[slot].start+fieldByte]))
			}
			selected.TxOut[fieldByte] = value
		}
	}
	selected.Script = selected.TxOut[selectedShape.script-selectedShape.start:]
	selected.Satoshis = parentUint64(api, selected.TxOut[:8])
	selected.Quantity = parentUint64(api, selected.Script[quantityOffsetInScript:quantityOffsetInScript+8])
	selected.Parent = BoundParentContext{
		Version:  raw[:4],
		Outputs:  raw[fields.outputs[0].start : fields.width-4],
		Locktime: raw[fields.width-4:],
		Inputs:   make([]BoundParentInput, len(fields.inputs)),
	}
	for i, input := range fields.inputs {
		selected.Parent.Inputs[i] = BoundParentInput{
			Outpoint:  raw[input.start : input.start+36],
			ScriptSig: raw[input.script:input.sequence],
			Sequence:  raw[input.sequence : input.sequence+4],
		}
	}
	return selected, nil
}

func (layout FixedParentLayout) fields() (fixedParentFields, error) {
	fields := fixedParentFields{width: 4}
	if len(layout.InputScriptLengths) == 0 || len(layout.OutputScriptLengths) == 0 {
		return fields, fmt.Errorf("expected nonempty legacy parent input and output vectors")
	}
	advance := func(width int) bool {
		if width < 0 || width > math.MaxInt-fields.width {
			return false
		}
		fields.width += width
		return true
	}
	compact := func(value int) bool {
		if value < 0 {
			return false
		}
		wire := parentCompactSize(uint64(value))
		fields.compact = append(fields.compact, compactField{fields.width, wire})
		return advance(len(wire))
	}
	invalidSize := fmt.Errorf("invalid script length or size overflow in fixed parent layout")
	if !compact(len(layout.InputScriptLengths)) {
		return fields, invalidSize
	}
	for _, scriptLength := range layout.InputScriptLengths {
		start := fields.width
		if !advance(36) || !compact(scriptLength) {
			return fields, invalidSize
		}
		script := fields.width
		if !advance(scriptLength) || !advance(4) {
			return fields, invalidSize
		}
		fields.inputs = append(fields.inputs, txInField{start, script, fields.width - 4})
	}
	if !compact(len(layout.OutputScriptLengths)) {
		return fields, invalidSize
	}
	for _, scriptLength := range layout.OutputScriptLengths {
		start := fields.width
		if !advance(8) || !compact(scriptLength) {
			return fields, invalidSize
		}
		script := fields.width
		if !advance(scriptLength) {
			return fields, invalidSize
		}
		fields.outputs = append(fields.outputs, txOutField{start, script, fields.width})
	}
	if !advance(4) {
		return fields, invalidSize
	}
	return fields, nil
}

func parentCompactSize(value uint64) []byte {
	switch {
	case value < 253:
		return []byte{byte(value)}
	case value <= math.MaxUint16:
		return binary.LittleEndian.AppendUint16([]byte{0xfd}, uint16(value))
	case value <= math.MaxUint32:
		return binary.LittleEndian.AppendUint32([]byte{0xfe}, uint32(value))
	default:
		return binary.LittleEndian.AppendUint64([]byte{0xff}, value)
	}
}

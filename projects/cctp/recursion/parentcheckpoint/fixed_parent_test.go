package parentcheckpoint

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
)

var testFixedParentLayout = FixedParentLayout{
	InputScriptLengths:  []int{259},
	OutputScriptLengths: []int{12, 253, 12},
}

type fixedParentTestCircuit struct {
	ActualOutpoint [36]frontend.Variable `gnark:",public"`
	Selected       [21]frontend.Variable `gnark:",public"`
	Quantity       frontend.Variable     `gnark:",public"`
	Satoshis       frontend.Variable     `gnark:",public"`
	Context        [32]frontend.Variable `gnark:",public"`
	Raw            []frontend.Variable
}

func (c *fixedParentTestCircuit) Define(api frontend.API) error {
	output, err := BindFixedParentOutput(api, c.Raw, c.ActualOutpoint[:], testFixedParentLayout, []int{0, 2}, 2)
	if err != nil {
		return err
	}
	for i, value := range output.TxOut {
		api.AssertIsEqual(value, c.Selected[i])
	}
	for i, value := range output.Script {
		api.AssertIsEqual(value, c.Selected[9+i])
	}
	api.AssertIsEqual(output.Quantity, c.Quantity)
	api.AssertIsEqual(output.Satoshis, c.Satoshis)
	var context []frontend.Variable
	context = append(context, output.Parent.Version...)
	for _, input := range output.Parent.Inputs {
		context = append(context, input.Outpoint...)
		context = append(context, input.ScriptSig...)
		context = append(context, input.Sequence...)
	}
	context = append(context, output.Parent.Outputs...)
	context = append(context, output.Parent.Locktime...)
	for i, value := range freeze.SHA256dBytes(api, context) {
		api.AssertIsEqual(value, c.Context[i])
	}
	return nil
}

func parentFixtureOutput(satoshis, quantity uint64, tag byte) []byte {
	output := binary.LittleEndian.AppendUint64(nil, satoshis)
	output = append(output, 12, 0x0b, tag)
	output = binary.LittleEndian.AppendUint64(output, quantity)
	return append(output, 0xdd, 0xee)
}

func fixedParentFixture() (raw, left, right []byte) {
	raw = []byte{2, 0, 0, 0, 1}
	raw = append(raw, bytes.Repeat([]byte{0x42}, 32)...)
	raw = binary.LittleEndian.AppendUint32(raw, 9)
	raw = append(raw, 0xfd, 3, 1, 0x4d, 0, 1)
	raw = append(raw, bytes.Repeat([]byte{0x7f}, 256)...)
	raw = binary.LittleEndian.AppendUint32(raw, 0x80000061)
	raw = append(raw, 3)
	left = parentFixtureOutput(1000, 640, 0xa1)
	right = parentFixtureOutput(1200, 384, 0xb2)
	raw = append(raw, left...)
	raw = binary.LittleEndian.AppendUint64(raw, 1)
	raw = append(raw, 0xfd, 253, 0)
	raw = append(raw, bytes.Repeat([]byte{0x51}, 253)...)
	raw = append(raw, right...)
	raw = binary.LittleEndian.AppendUint32(raw, 3)
	return raw, left, right
}

func fixedParentAssignment(raw []byte, txid [32]byte, vout uint32, selected []byte) *fixedParentTestCircuit {
	witness := &fixedParentTestCircuit{
		Raw:      make([]frontend.Variable, len(raw)),
		Quantity: binary.LittleEndian.Uint64(selected[11:19]),
		Satoshis: binary.LittleEndian.Uint64(selected[:8]),
	}
	for i, value := range raw {
		witness.Raw[i] = value
	}
	for i, value := range binary.LittleEndian.AppendUint32(txid[:], vout) {
		witness.ActualOutpoint[i] = value
	}
	for i, value := range selected {
		witness.Selected[i] = value
	}
	// Reassemble the fields from their independently known wire offsets.
	context := append(bytes.Clone(raw[:4]), raw[5:41]...)
	context = append(context, raw[44:307]...)
	context = append(context, raw[308:]...)
	for i, value := range hash256(context) {
		witness.Context[i] = value
	}
	return witness
}

func TestDirectFixedParentOpening(t *testing.T) {
	raw, left, right := fixedParentFixture()
	width, err := testFixedParentLayout.SerializedSize()
	if err != nil || width != 618 || len(raw) != width {
		t.Fatalf("unexpected fixed wire length %d, err=%v", width, err)
	}
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &fixedParentTestCircuit{Raw: make([]frontend.Variable, width)})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixed %d-byte parent, %d constraints", width, ccs.GetNbConstraints())
	solve := func(t *testing.T, assignment *fixedParentTestCircuit, accepted bool) {
		t.Helper()
		witness, err := frontend.NewWitness(assignment, field)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(witness); (err == nil) != accepted {
			t.Fatalf("unexpected solver result, wanted valid=%t: %v", accepted, err)
		}
	}
	txid := hash256(raw)
	solve(t, fixedParentAssignment(raw, txid, 0, left), true)
	solve(t, fixedParentAssignment(raw, txid, 2, right), true)

	swapped := bytes.Clone(raw)
	copy(swapped[308:329], right)
	copy(swapped[593:614], left)
	wrongSlotBytes := fixedParentAssignment(raw, txid, 0, left)
	// 256 + 256*(-1) still equals zero without independent byte ranges.
	wrongSlotBytes.ActualOutpoint[32], wrongSlotBytes.ActualOutpoint[33] = 256, -1
	wrongContext := fixedParentAssignment(raw, txid, 0, left)
	wrongContext.Context[0] = wrongContext.Context[0].(byte) ^ 1
	for _, test := range []struct {
		name       string
		assignment *fixedParentTestCircuit
	}{
		{"non-token-slot", fixedParentAssignment(raw, txid, 1, left)},
		{"out-of-range-slot", fixedParentAssignment(raw, txid, 256, left)},
		{"nonbyte-vout", wrongSlotBytes},
		{"wrong-slot-opening", fixedParentAssignment(raw, txid, 2, left)},
		{"unrelated-predecessor-context", wrongContext},
		{"swapped-raw-original-txid", fixedParentAssignment(swapped, txid, 0, left)},
		{"swapped-raw-updated-txid-old-opening", fixedParentAssignment(swapped, hash256(swapped), 0, left)},
	} {
		t.Run(test.name, func(t *testing.T) { solve(t, test.assignment, false) })
	}

	for _, boundary := range []struct {
		name  string
		index int
		value byte
	}{
		{"wrong-input-compact-size", 42, 0xfc},
		{"fake-padding-at-output-count", 307, 0x80},
		{"overlong-unselected-output-compact-size", 338, 0xfc},
		{"unselected-output-satoshis-out-of-range", 336, 0x80},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			mutant := bytes.Clone(raw)
			mutant[boundary.index] = boundary.value
			solve(t, fixedParentAssignment(mutant, hash256(mutant), 0, left), false)
		})
	}
	if _, err := frontend.Compile(field, r1cs.NewBuilder, &fixedParentTestCircuit{
		Raw: make([]frontend.Variable, width+64),
	}); err == nil {
		t.Fatal("accepted caller-supplied SHA padding after the complete legacy parent")
	}
}

func TestInvalidFixedParentLayouts(t *testing.T) {
	for _, layout := range []FixedParentLayout{
		{},
		{InputScriptLengths: []int{0}, OutputScriptLengths: []int{-1}},
		{InputScriptLengths: []int{math.MaxInt}, OutputScriptLengths: []int{0}},
	} {
		if _, err := layout.SerializedSize(); err == nil {
			t.Fatalf("accepted invalid fixed legacy parent layout %+v", layout)
		}
	}
}

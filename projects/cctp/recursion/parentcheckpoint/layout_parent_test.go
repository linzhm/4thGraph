package parentcheckpoint

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var testParentLayouts = []ParentOutputLayout{
	{Layout: FixedParentLayout{InputScriptLengths: []int{5}, OutputScriptLengths: []int{1, 12, 1}}, EligibleVouts: []int{1}},
	{Layout: FixedParentLayout{InputScriptLengths: []int{253, 0}, OutputScriptLengths: []int{12, 12, 1, 1}}, EligibleVouts: []int{0, 1}},
}

type layoutParentTestCircuit struct {
	Outpoint     [36]frontend.Variable `gnark:",public"`
	Selected     [21]frontend.Variable `gnark:",public"`
	LastTxOut    [10]frontend.Variable `gnark:",public"`
	FirstPrevout [36]frontend.Variable `gnark:",public"`
	LastSequence [4]frontend.Variable  `gnark:",public"`
	Locktime     [4]frontend.Variable  `gnark:",public"`
	Inputs       frontend.Variable     `gnark:",public"`
	Outputs      frontend.Variable     `gnark:",public"`
	Satoshis     frontend.Variable     `gnark:",public"`
	LayoutIndex  frontend.Variable
	Raw          []frontend.Variable
}

func (c *layoutParentTestCircuit) Define(api frontend.API) error {
	output, err := BindParentOutput(api, c.Raw, c.Outpoint[:], c.LayoutIndex, testParentLayouts)
	if err != nil {
		return err
	}
	for i, value := range output.TxOut {
		api.AssertIsEqual(value, c.Selected[i])
	}
	for i, value := range output.Script {
		api.AssertIsEqual(value, c.Selected[9+i])
	}
	api.AssertIsEqual(output.Satoshis, c.Satoshis)
	for _, layout := range output.Layouts {
		assert := func(value, expected frontend.Variable) {
			api.AssertIsEqual(api.Mul(layout.Selector, api.Sub(value, expected)), 0)
		}
		context := layout.Context
		assert(len(context.Inputs), c.Inputs)
		assert(len(context.TxOuts), c.Outputs)
		lastOutput := context.TxOuts[len(context.TxOuts)-1]
		for i, value := range c.LastTxOut {
			assert(lastOutput[i], value)
			assert(context.Outputs[len(context.Outputs)-len(lastOutput)+i], value)
		}
		for i, value := range context.Inputs[0].Outpoint {
			assert(value, c.FirstPrevout[i])
		}
		for i, value := range context.Inputs[len(context.Inputs)-1].Sequence {
			assert(value, c.LastSequence[i])
		}
		for i, value := range context.Locktime {
			assert(value, c.Locktime[i])
		}
	}
	return nil
}

type layoutParentFixture struct {
	raw       []byte
	inputWire [][]byte
	txOuts    [][]byte
	outStart  int
}

func makeLayoutParentFixture(layout int) layoutParentFixture {
	input := func(tag byte, compact, script []byte) []byte {
		outpoint := binary.LittleEndian.AppendUint32(bytes.Repeat([]byte{tag}, 32), uint32(tag)+4)
		wire := append(outpoint, compact...)
		wire = append(wire, script...)
		return binary.LittleEndian.AppendUint32(wire, 0x80000000+uint32(tag))
	}
	shortOutput := func(satoshis uint64, tag byte) []byte {
		return append(binary.LittleEndian.AppendUint64(nil, satoshis), 1, tag)
	}
	var fixture layoutParentFixture
	if layout == 0 {
		fixture.inputWire = [][]byte{input(0x41, []byte{5}, []byte{4, 1, 2, 3, 4})}
		fixture.txOuts = [][]byte{shortOutput(900, 0x51), parentFixtureOutput(1000, 640, 0xa1), shortOutput(0, 0x53)}
	} else {
		script := append([]byte{0x4c, 251}, bytes.Repeat([]byte{0xcd}, 251)...)
		fixture.inputWire = [][]byte{input(0x61, []byte{0xfd, 253, 0}, script), input(0x65, []byte{0}, nil)}
		fixture.txOuts = [][]byte{parentFixtureOutput(1100, 600, 0xb1), parentFixtureOutput(1200, 424, 0xb2),
			shortOutput(2, 0x52), shortOutput(0, 0x54)}
	}
	raw := []byte{2, 0, 0, 0, byte(len(fixture.inputWire))}
	for _, wire := range fixture.inputWire {
		raw = append(raw, wire...)
	}
	raw = append(raw, byte(len(fixture.txOuts)))
	fixture.outStart = len(raw)
	for _, wire := range fixture.txOuts {
		raw = append(raw, wire...)
	}
	fixture.raw = binary.LittleEndian.AppendUint32(raw, uint32(layout)+7)
	return fixture
}

func (f layoutParentFixture) assignment(raw []byte, txid [32]byte, vout, layout, width int) *layoutParentTestCircuit {
	c := &layoutParentTestCircuit{
		Raw: make([]frontend.Variable, width), LayoutIndex: layout, Inputs: len(f.inputWire), Outputs: len(f.txOuts),
	}
	for i := range c.Raw {
		c.Raw[i] = byte(0)
	}
	copyBytes := func(dst []frontend.Variable, src []byte) {
		for i, value := range src {
			dst[i] = value
		}
	}
	copyBytes(c.Raw, raw)
	copyBytes(c.Outpoint[:], binary.LittleEndian.AppendUint32(txid[:], uint32(vout)))
	copyBytes(c.Selected[:], f.txOuts[1])
	if layout == 1 && vout == 0 {
		copyBytes(c.Selected[:], f.txOuts[0])
	}
	selectedSatoshis := make([]byte, 8)
	for i := range selectedSatoshis {
		selectedSatoshis[i] = c.Selected[i].(byte)
	}
	c.Satoshis = binary.LittleEndian.Uint64(selectedSatoshis)
	copyBytes(c.LastTxOut[:], f.txOuts[len(f.txOuts)-1])
	copyBytes(c.FirstPrevout[:], f.inputWire[0][:36])
	lastInput := f.inputWire[len(f.inputWire)-1]
	copyBytes(c.LastSequence[:], lastInput[len(lastInput)-4:])
	copyBytes(c.Locktime[:], f.raw[len(f.raw)-4:])
	return c
}

func TestBindParentOutputAcrossWireLayouts(t *testing.T) {
	mint, transfer := makeLayoutParentFixture(0), makeLayoutParentFixture(1)
	width, err := MaxParentSerializedSize(testParentLayouts)
	if err != nil || width != len(transfer.raw) || len(mint.raw) >= width {
		t.Fatalf("unexpected bounded raw width %d, err=%v", width, err)
	}
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &layoutParentTestCircuit{Raw: make([]frontend.Variable, width)})
	if err != nil {
		t.Fatal(err)
	}
	if commitments := len(ccs.GetCommitments().CommitmentIndexes()); commitments != 0 {
		t.Fatalf("plain multi-layout binding emitted %d commitments", commitments)
	}
	t.Logf("parents of %d and %d bytes, %d constraints", len(mint.raw), width, ccs.GetNbConstraints())
	solve := func(t *testing.T, assignment *layoutParentTestCircuit, accepted bool) {
		t.Helper()
		witness, err := frontend.NewWitness(assignment, field)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(witness); (err == nil) != accepted {
			t.Fatalf("unexpected solver result, wanted valid=%t: %v", accepted, err)
		}
	}
	mintClaim := func(vout int) *layoutParentTestCircuit {
		return mint.assignment(mint.raw, hash256(mint.raw), vout, 0, width)
	}
	transferClaim := func(vout int) *layoutParentTestCircuit {
		return transfer.assignment(transfer.raw, hash256(transfer.raw), vout, 1, width)
	}
	solve(t, mintClaim(1), true)
	solve(t, transferClaim(0), true)
	solve(t, transferClaim(1), true)

	tail := mintClaim(1)
	tail.Raw[len(mint.raw)] = byte(0x80)
	wrongLayout := mintClaim(1)
	wrongLayout.LayoutIndex = 1
	noLayout := mintClaim(1)
	noLayout.LayoutIndex = 2
	wrongReceipt := mintClaim(1)
	wrongReceipt.LastTxOut[9] = byte(0x54)
	badCompact := bytes.Clone(transfer.raw)
	badCompact[41] = 0xfc
	badOutputCompact := bytes.Clone(transfer.raw)
	badOutputCompact[transfer.outStart+8] = 11
	badAmount := bytes.Clone(transfer.raw)
	badAmount[transfer.outStart+7] = 0x80 // Invalid even in unselected vout zero.
	spliced := bytes.Clone(mint.raw)
	copy(spliced[mint.outStart+len(mint.txOuts[0]):], transfer.txOuts[1])
	paddedMint := append(bytes.Clone(mint.raw), make([]byte, width-len(mint.raw))...)
	for _, test := range []struct {
		name       string
		assignment *layoutParentTestCircuit
	}{
		{"mint-state-vout", mintClaim(0)},
		{"transfer-receipt-vout", transferClaim(3)},
		{"wrong-wire-layout", wrongLayout},
		{"layout-out-of-range", noLayout},
		{"wrong-last-receipt", wrongReceipt},
		{"nonzero-unused-tail", tail},
		{"hash-of-zero-padded-buffer", mint.assignment(mint.raw, hash256(paddedMint), 1, 0, width)},
		{"noncanonical-input-length", transfer.assignment(badCompact, hash256(badCompact), 1, 1, width)},
		{"wrong-output-length", transfer.assignment(badOutputCompact, hash256(badOutputCompact), 1, 1, width)},
		{"invalid-unselected-output-satoshis", transfer.assignment(badAmount, hash256(badAmount), 1, 1, width)},
		{"splice-under-original-txid", mint.assignment(spliced, hash256(mint.raw), 1, 0, width)},
		{"splice-under-unrelated-output-claim", mint.assignment(spliced, hash256(spliced), 1, 0, width)},
	} {
		t.Run(test.name, func(t *testing.T) { solve(t, test.assignment, false) })
	}
}

func TestRejectInvalidParentLayoutSets(t *testing.T) {
	for _, layouts := range [][]ParentOutputLayout{
		nil,
		{testParentLayouts[0], testParentLayouts[0]},
		{{Layout: testParentLayouts[0].Layout, EligibleVouts: []int{3}}},
		{{Layout: testParentLayouts[1].Layout, EligibleVouts: []int{2, 1}}},
	} {
		if _, err := MaxParentSerializedSize(layouts); err == nil {
			t.Fatalf("accepted invalid finite parent layouts %+v", layouts)
		}
	}
}

type heterogeneousParentCircuit struct {
	Outpoint [36]frontend.Variable `gnark:",public"`
	TxOut    [21]frontend.Variable `gnark:",public"`
	Size     frontend.Variable     `gnark:",public"`
	Satoshis frontend.Variable     `gnark:",public"`
	Layout   frontend.Variable
	Raw      []frontend.Variable
	Flatten  bool `gnark:"-"`
}

func (c *heterogeneousParentCircuit) Define(api frontend.API) error {
	layouts := []ParentOutputLayout{
		{Layout: testParentLayouts[0].Layout, EligibleVouts: []int{0, 1}},
		testParentLayouts[1],
	}
	if c.Flatten {
		_, err := BindParentOutput(api, c.Raw, c.Outpoint[:], c.Layout, layouts)
		return err
	}
	parent, err := BindParentTransaction(api, c.Raw, c.Outpoint[:], c.Layout, layouts)
	if err != nil {
		return err
	}
	for _, layout := range parent.Layouts {
		for _, output := range layout.EligibleOutputs {
			assert := func(value, expected frontend.Variable) {
				api.AssertIsEqual(api.Mul(output.Selector, api.Sub(value, expected)), 0)
			}
			assert(parent.Vout, output.Vout)
			assert(output.Satoshis, c.Satoshis)
			assert(len(output.TxOut), c.Size)
			for i, value := range output.TxOut {
				assert(value, c.TxOut[i])
			}
			for i, value := range output.Script {
				assert(value, c.TxOut[9+i])
			}
		}
	}
	return nil
}

func TestBindParentTransactionWithDifferentOutputWidths(t *testing.T) {
	mint, transfer := makeLayoutParentFixture(0), makeLayoutParentFixture(1)
	layouts := []ParentOutputLayout{
		{Layout: testParentLayouts[0].Layout, EligibleVouts: []int{0, 1}},
		testParentLayouts[1],
	}
	width, err := MaxParentSerializedSize(layouts)
	if err != nil || width != len(transfer.raw) {
		t.Fatalf("unexpected heterogeneous parent width %d: %v", width, err)
	}
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &heterogeneousParentCircuit{Raw: make([]frontend.Variable, width)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := frontend.Compile(field, r1cs.NewBuilder, &heterogeneousParentCircuit{
		Raw: make([]frontend.Variable, width), Flatten: true,
	}); err == nil {
		t.Fatal("flat TxOut binding accepted heterogeneous output widths")
	}
	for _, test := range []struct {
		name                    string
		fixture                 layoutParentFixture
		layout, vout, claimVout int
		valid                   bool
	}{
		{"mint-state", mint, 0, 0, 0, true},
		{"mint-token", mint, 0, 1, 1, true},
		{"transfer-token", transfer, 1, 0, 0, true},
		{"claim-mint-state-at-token-slot", mint, 0, 1, 0, false},
		{"claim-transfer-token-at-other-token-slot", transfer, 1, 1, 0, false},
		{"mint-receipt", mint, 0, 2, 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claimed := test.fixture.txOuts[test.claimVout]
			assignment := &heterogeneousParentCircuit{
				Raw: make([]frontend.Variable, width), Layout: test.layout, Size: len(claimed),
				Satoshis: binary.LittleEndian.Uint64(claimed[:8]),
			}
			for i, value := range append(bytes.Clone(test.fixture.raw), make([]byte, width-len(test.fixture.raw))...) {
				assignment.Raw[i] = value
			}
			for i, value := range append(bytes.Clone(claimed), make([]byte, len(assignment.TxOut)-len(claimed))...) {
				assignment.TxOut[i] = value
			}
			txid := hash256(test.fixture.raw)
			for i, value := range binary.LittleEndian.AppendUint32(txid[:], uint32(test.vout)) {
				assignment.Outpoint[i] = value
			}
			witness, err := frontend.NewWitness(assignment, field)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ccs.Solve(witness); (err == nil) != test.valid {
				t.Fatalf("unexpected solver result, wanted valid=%t: %v", test.valid, err)
			}
		})
	}
}

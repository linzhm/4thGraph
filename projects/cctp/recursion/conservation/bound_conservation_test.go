package conservation

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/parentcheckpoint"
)

const (
	fixtureTokenPrefix = "\x12BSV/CCTP/token/v2\x00\x4a"
	fixtureMetadata    = freeze.FrozenOffset + 1 - 8
	fixtureTokenScript = len(fixtureTokenPrefix) + fixtureMetadata + 1
	fixtureTxOutSize   = 8 + 1 + fixtureTokenScript
	fixtureParentSize  = 4 + 1 + 41 + 1 + fixtureTxOutSize + 4
)

// The fixture isolates txid/vout authentication and conservation. Its one-byte
// suffix is not a production token lock. The production recursive verifier
// still needs to authenticate the predecessor statement and policy.
type boundConservationFixture struct {
	PrevoutHash [32]frontend.Variable `gnark:",public"`
	OutHash     [32]frontend.Variable `gnark:",public"`
	Outpoints   [3][freeze.OutpointSize]frontend.Variable
	Parents     [2][fixtureParentSize]frontend.Variable
	Outputs     [2 * fixtureTxOutSize]frontend.Variable
}

var fixtureFeeOutpoint = [freeze.OutpointSize]byte{0x7f}

func (c *boundConservationFixture) Define(api frontend.API) error {
	fixtureLayout := parentcheckpoint.FixedParentLayout{
		InputScriptLengths:  []int{0},
		OutputScriptLengths: []int{fixtureTokenScript},
	}
	var records []frontend.Variable
	appendState := func(txOut []frontend.Variable) {
		api.AssertIsEqual(txOut[8], fixtureTokenScript)
		for i, value := range []byte(fixtureTokenPrefix) {
			api.AssertIsEqual(txOut[9+i], value)
		}
		api.AssertIsEqual(txOut[fixtureTxOutSize-1], 0x51)
		records = append(records, txOut[:8]...)
		records = append(records, txOut[9+len(fixtureTokenPrefix):fixtureTxOutSize-1]...)
		// All four fixture outputs use the same literal lock suffix.
		for i := 0; i < 32; i++ {
			records = append(records, 0)
		}
	}
	var orderedPrevouts []frontend.Variable
	for i := range c.Outpoints {
		orderedPrevouts = append(orderedPrevouts, c.Outpoints[i][:]...)
	}
	for i, value := range freeze.SHA256dBytes(api, orderedPrevouts) {
		api.AssertIsEqual(value, c.PrevoutHash[i])
	}
	// This fixed profile has one approved fee/verification input and two token
	// slots. The fee outpoint contributes no state record to the sum.
	for i, value := range fixtureFeeOutpoint {
		api.AssertIsEqual(c.Outpoints[0][i], value)
	}
	for i := range c.Parents {
		output, err := parentcheckpoint.BindFixedParentOutput(api, c.Parents[i][:], c.Outpoints[i+1][:],
			fixtureLayout, []int{0}, len(fixtureTokenPrefix)+freeze.QuantityOffset-8)
		if err != nil {
			return err
		}
		appendState(output.TxOut)
	}
	AssertDistinctOutpoints(api, c.Outpoints[:])
	for i, value := range freeze.SHA256dBytes(api, c.Outputs[:]) {
		api.AssertIsEqual(value, c.OutHash[i])
	}
	appendState(c.Outputs[:fixtureTxOutSize])
	appendState(c.Outputs[fixtureTxOutSize:])
	return Assert2x2(api, records)
}

func TestConservationUsesTheOutputsOfTheActualParents(t *testing.T) {
	ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &boundConservationFixture{})
	if err != nil {
		t.Fatal(err)
	}
	bindPrevouts := func(assignment *boundConservationFixture) {
		raw := make([]byte, 0, len(assignment.Outpoints)*freeze.OutpointSize)
		for _, outpoint := range assignment.Outpoints {
			for _, value := range outpoint {
				raw = append(raw, value.(byte))
			}
		}
		first := sha256.Sum256(raw)
		for i, value := range sha256.Sum256(first[:]) {
			assignment.PrevoutHash[i] = value
		}
	}
	makeAssignment := func(firstInput, firstOutput uint64) boundConservationFixture {
		statement := conservationVector()
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(stateAt(&statement, i), 1000)
		}
		setQuantity(&statement, 0, firstInput)
		setQuantity(&statement, 2, firstOutput)
		output := func(index int) []byte {
			record := stateAt(&statement, index)
			raw := append([]byte{}, record[:8]...)
			raw = append(raw, byte(fixtureTokenScript))
			raw = append(raw, fixtureTokenPrefix...)
			raw = append(raw, record[8:freeze.FrozenOffset+1]...)
			return append(raw, 0x51)
		}
		var assignment boundConservationFixture
		for i, value := range fixtureFeeOutpoint {
			assignment.Outpoints[0][i] = value
		}
		for i := range assignment.Parents {
			raw := []byte{2, 0, 0, 0, 1}
			position := make([]byte, 36)
			position[0] = byte(i + 1)
			raw = append(raw, position...)
			raw = append(raw, 0, 0xff, 0xff, 0xff, 0xff, 1)
			raw = append(raw, output(i)...)
			raw = binary.LittleEndian.AppendUint32(raw, 0)
			if len(raw) != fixtureParentSize {
				t.Fatalf("unexpected parent width %d", len(raw))
			}
			for j, value := range raw {
				assignment.Parents[i][j] = value
			}
			first := sha256.Sum256(raw)
			for j, value := range sha256.Sum256(first[:]) {
				assignment.Outpoints[i+1][j] = value
			}
			for j := 32; j < 36; j++ {
				assignment.Outpoints[i+1][j] = byte(0)
			}
		}
		bindPrevouts(&assignment)
		outputs := append(output(2), output(3)...)
		for i, value := range outputs {
			assignment.Outputs[i] = value
		}
		first := sha256.Sum256(outputs)
		for i, value := range sha256.Sum256(first[:]) {
			assignment.OutHash[i] = value
		}
		return assignment
	}
	solve := func(assignment boundConservationFixture, valid bool) {
		t.Helper()
		witness, err := frontend.NewWitness(&assignment, fr.Modulus())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(witness); (err == nil) != valid {
			t.Fatalf("unexpected solver result, wanted valid=%t: %v", valid, err)
		}
	}
	valid := makeAssignment(640, 700)
	solve(valid, true)
	// Balance against a substituted amount but keep the actual input outpoints.
	forged := makeAssignment(641, 701)
	forged.Outpoints = valid.Outpoints
	forged.PrevoutHash = valid.PrevoutHash
	solve(forged, false)
	// Authenticate both byte strings but change the successor quantity alone.
	solve(makeAssignment(640, 701), false)
	// A real parent hash does not authorize selecting another output slot.
	wrongSlot := valid
	wrongSlot.Outpoints[1][32] = byte(1)
	bindPrevouts(&wrongSlot)
	solve(wrongSlot, false)
	// Counting the very same UTXO twice would otherwise balance these outputs.
	duplicate := makeAssignment(640, 956)
	duplicate.Parents[1] = duplicate.Parents[0]
	duplicate.Outpoints[2] = duplicate.Outpoints[1]
	bindPrevouts(&duplicate)
	solve(duplicate, false)
	omitted := valid
	omitted.Outpoints[2] = omitted.Outpoints[0]
	bindPrevouts(&omitted)
	solve(omitted, false)
	wrongFee := valid
	wrongFee.Outpoints[0] = makeAssignment(100, 700).Outpoints[1]
	bindPrevouts(&wrongFee)
	solve(wrongFee, false)
	// Even swapping both private openings cannot change authenticated vin order.
	reordered := valid
	reordered.Outpoints[1], reordered.Outpoints[2] = reordered.Outpoints[2], reordered.Outpoints[1]
	reordered.Parents[0], reordered.Parents[1] = reordered.Parents[1], reordered.Parents[0]
	solve(reordered, false)
	// An actual output hash covering an additional output cannot be opened by
	// only the two outputs counted by the circuit.
	actualOutputs := make([]byte, len(valid.Outputs), len(valid.Outputs)+fixtureTxOutSize)
	for i, value := range valid.Outputs {
		actualOutputs[i] = value.(byte)
	}
	actualOutputs = append(actualOutputs, actualOutputs[:fixtureTxOutSize]...)
	first := sha256.Sum256(actualOutputs)
	omittedOutput := valid
	for i, value := range sha256.Sum256(first[:]) {
		omittedOutput.OutHash[i] = value
	}
	solve(omittedOutput, false)
}

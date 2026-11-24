package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/keycommit"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/parentcheckpoint"
)

// The fixture lock isolates transaction and proof wiring. It is deliberately
// not an on-chain authorization or an issuance covenant.
const wireFixtureTokenPrefix = "\x12BSV/CCTP/token/v2\x00\x4a"
const wireFixtureTokenLen = len(wireFixtureTokenPrefix) + tokenMetadataSize + 1
const wireFixtureTokenOutLen = 9 + wireFixtureTokenLen
const wireFixtureReceiptScriptLen = 68
const wireFixtureReceiptOutLen = 9 + wireFixtureReceiptScriptLen
const wireFixtureParentLen = 4 + 1 + 41 + 1 + wireFixtureTokenOutLen + wireFixtureReceiptOutLen + 4

type wireTransferFixture struct {
	Digest    [2]frontend.Variable `gnark:",public"`
	SelfID    [32]frontend.Variable
	Outpoints [][36]frontend.Variable
	Outputs   [4][wireFixtureTokenOutLen]frontend.Variable
	Receipt   [wireFixtureReceiptOutLen]frontend.Variable
	Parents   [][wireFixtureParentLen]frontend.Variable
	Proofs    []Proof
	Key       keycommit.Key

	pad padding `gnark:"-"`
}

func (c *wireTransferFixture) Define(api frontend.API) error {
	code, err := hex.DecodeString(compactChronicleScriptCode)
	if err != nil {
		return err
	}
	profile := wireTransferProfile{
		VerifierScriptCode: code, TokenPrefix: []byte(wireFixtureTokenPrefix), TokenSuffix: []byte{0x51},
	}
	var asset [32]frontend.Variable
	for i := range asset {
		asset[i] = i
	}
	layout := parentcheckpoint.FixedParentLayout{
		InputScriptLengths: []int{0}, OutputScriptLengths: []int{wireFixtureTokenLen, wireFixtureReceiptScriptLen},
	}
	var priors [][]frontend.Variable
	digests := make([][32]frontend.Variable, len(c.Parents))
	for i := range c.Parents {
		parent, err := parentcheckpoint.BindFixedParentOutput(api, c.Parents[i][:], c.Outpoints[i+1][:], layout, []int{0})
		if err != nil {
			return err
		}
		priors = append(priors, parent.TxOut)
		digests[i], err = committedParentDigest(api, parent.Parent, 0, code, asset, c.SelfID,
			variableOutpoint(wireFixtureOutpoint(byte(i+1))))
		if err != nil {
			return err
		}
	}
	current := parentcheckpoint.BoundParentContext{Version: []frontend.Variable{2, 0, 0, 0}, Locktime: []frontend.Variable{0, 0, 0, 0}}
	for i := range c.Outpoints {
		sequence := []frontend.Variable{0xff, 0xff, 0xff, 0xff}
		if i == 0 {
			sequence = []frontend.Variable{0x61, 0, 0, 0x80}
		}
		current.Inputs = append(current.Inputs, parentcheckpoint.BoundParentInput{
			Outpoint: c.Outpoints[i][:], Sequence: sequence,
		})
	}
	for i := range c.Outputs {
		current.TxOuts = append(current.TxOuts, c.Outputs[i][:])
	}
	current.TxOuts = append(current.TxOuts, c.Receipt[:])
	digest, err := wireTransferDigest(api, current, priors, digests, profile, asset, c.SelfID,
		variableOutpoint(wireFixtureOutpoint(0x79)))
	if err != nil {
		return err
	}
	byteAPI, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	keyID := make([]uints.U8, len(c.SelfID))
	result := make([]uints.U8, len(digest))
	for i := range keyID {
		keyID[i], result[i] = byteAPI.ValueOf(c.SelfID[i]), byteAPI.ValueOf(digest[i])
	}
	if err := keycommit.Assert(api, &c.Key, uint128Pair(api, keyID)); err != nil {
		return err
	}
	for i, value := range uint128Pair(api, result) {
		api.AssertIsEqual(value, c.Digest[i])
	}
	active := make([]frontend.Variable, len(c.Parents))
	for i := range active {
		active[i] = 1
	}
	_, err = assertPredecessorProofs(api, byteAPI, &c.Key, c.pad, active, digests, c.Proofs)
	return err
}

func wireFixtureOutpoint(marker byte) (out [36]byte) {
	out[0] = marker
	return out
}

func variableOutpoint(raw [36]byte) (out [36]frontend.Variable) {
	for i, value := range raw {
		out[i] = value
	}
	return out
}

func wireFixtureSHA256d(raw []byte) [32]byte {
	first := sha256.Sum256(raw)
	return sha256.Sum256(first[:])
}

func wireFixtureToken(quantity, satoshis uint64, owner byte) []byte {
	raw := binary.LittleEndian.AppendUint64(nil, satoshis)
	raw = append(raw, byte(wireFixtureTokenLen))
	raw = append(raw, wireFixtureTokenPrefix...)
	for i := 0; i < 32; i++ {
		raw = append(raw, byte(i))
	}
	raw = binary.LittleEndian.AppendUint64(raw, quantity)
	raw = append(raw, 2, owner)
	raw = append(raw, make([]byte, 31)...)
	return append(raw, 0, 0x51)
}

func wireFixtureReceipt(digests [][32]byte) []byte {
	predecessors := append([]byte(predecessorCommitmentDomain), byte(len(digests)))
	for i := range digests {
		predecessors = append(predecessors, digests[i][:]...)
	}
	predecessors = append(predecessors, make([]byte, (committedParentSlots-len(digests))*32)...)
	root := wireFixtureSHA256d(predecessors)
	output := append(committedReceiptPrefix(), byte(len(digests)))
	return append(output, root[:]...)
}

func wireFixtureEncode(inputs [][36]byte, outputs [][]byte, scriptCode []byte) []byte {
	raw := []byte{2, 0, 0, 0, byte(len(inputs))}
	for i, input := range inputs {
		raw = append(raw, input[:]...)
		if i == 0 {
			raw = append(raw, byte(len(scriptCode)))
			raw = append(raw, scriptCode...)
			raw = append(raw, 0x61, 0, 0, 0x80)
		} else {
			raw = append(raw, 0, 0xff, 0xff, 0xff, 0xff)
		}
	}
	raw = append(raw, byte(len(outputs)))
	for _, output := range outputs {
		raw = append(raw, output...)
	}
	return append(raw, 0, 0, 0, 0)
}

func wireFixtureDigest(inputs [][36]byte, outputs [][]byte, scriptCode []byte, selfID [32]byte) [32]byte {
	preimage := append(wireFixtureEncode(inputs, outputs, scriptCode), 0x61, 0, 0, 0)
	context := wireFixtureSHA256d(preimage)
	message := []byte(committedContinuityDomain)
	for i := 0; i < 32; i++ {
		message = append(message, byte(i))
	}
	message = append(message, selfID[:]...)
	message = append(message, context[:]...)
	receipt := outputs[len(outputs)-1]
	message = append(message, receipt[len(receipt)-committedReceiptPayloadSize:]...)
	return wireFixtureSHA256d(message)
}

func TestWireTransfersBindBalanceAndProofForOneOrFourParents(t *testing.T) {
	if os.Getenv("CCTP_CONTINUITY_SOLVER_TEST") != "1" {
		t.Skip("set CCTP_CONTINUITY_SOLVER_TEST=1 for composed transfer solving")
	}
	field := fr.Modulus()
	source, err := frontend.Compile(field, r1cs.NewBuilder, &literalParentStatement{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(source)
	if err != nil {
		t.Fatal(err)
	}
	pad, _, err := loadPadding()
	if err != nil {
		t.Fatal(err)
	}
	state := &provingState{pad: pad}
	if err := state.useKey(vk.(*native.VerifyingKey)); err != nil {
		t.Fatal(err)
	}
	code, err := hex.DecodeString(compactChronicleScriptCode)
	if err != nil {
		t.Fatal(err)
	}

	for _, inputCount := range []int{1, 4} {
		t.Run(fmt.Sprintf("%d-to-4", inputCount), func(t *testing.T) {
			template := wireTransferFixture{
				Outpoints: make([][36]frontend.Variable, inputCount+1),
				Parents:   make([][wireFixtureParentLen]frontend.Variable, inputCount),
				Proofs:    make([]Proof, inputCount), Key: keycommit.Placeholder(), pad: pad,
			}
			for i := range template.Proofs {
				template.Proofs[i] = circuitTemplate(pad).Proofs[0]
			}
			ccs, err := frontend.Compile(field, r1cs.NewBuilder, &template)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d constraints for %d real parent slots and four ordered successors", ccs.GetNbConstraints(), inputCount)

			inputs := make([][36]byte, inputCount+1)
			inputs[0] = wireFixtureOutpoint(0x79)
			digests := make([][32]byte, inputCount)
			wire := wireTransferFixture{
				Key: state.key, Outpoints: make([][36]frontend.Variable, inputCount+1),
				Parents: make([][wireFixtureParentLen]frontend.Variable, inputCount), Proofs: make([]Proof, inputCount),
			}
			for i, value := range state.keyDigest {
				wire.SelfID[i] = value
			}
			for i := range digests {
				parentInputs := [][36]byte{wireFixtureOutpoint(byte(i + 1))}
				parentOutputs := [][]byte{wireFixtureToken(1024/uint64(inputCount), 4000/uint64(inputCount), byte(i+1)), wireFixtureReceipt(nil)}
				parent := wireFixtureEncode(parentInputs, parentOutputs, nil)
				for j, value := range parent {
					wire.Parents[i][j] = value
				}
				txid := wireFixtureSHA256d(parent)
				copy(inputs[i+1][:], txid[:])
				digests[i] = wireFixtureDigest(parentInputs, parentOutputs, code, state.keyDigest)
				pair := limbs(digests[i])
				vals := [2]frontend.Variable{pair[0], pair[1]}
				w, err := frontend.NewWitness(&literalParentStatement{Public: vals, Value: vals}, field)
				if err != nil {
					t.Fatal(err)
				}
				proof, err := groth16.Prove(source, pk, w, recursive.GetNativeProverOptions(field, field))
				if err != nil {
					t.Fatal(err)
				}
				wire.Proofs[i], err = recursive.ValueOfProof[G1, G2](proof)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, value := range inputs {
				wire.Outpoints[i] = variableOutpoint(value)
			}
			solve := func(outputs [][]byte, accept bool) {
				t.Helper()
				candidate := wire
				for i := range candidate.Outputs {
					for j, value := range outputs[i] {
						candidate.Outputs[i][j] = value
					}
				}
				for i, value := range outputs[4] {
					candidate.Receipt[i] = value
				}
				pair := limbs(wireFixtureDigest(inputs, outputs, code, state.keyDigest))
				candidate.Digest = [2]frontend.Variable{pair[0], pair[1]}
				w, challenge, err := solverWitness(&candidate)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ccs.Solve(w, challenge); (err == nil) != accept {
					t.Fatalf("expected accept=%t, solver returned %v", accept, err)
				}
			}
			outputs := make([][]byte, 5)
			for i := range outputs[:4] {
				outputs[i] = wireFixtureToken(256, 1000, byte(i+10))
			}
			outputs[4] = wireFixtureReceipt(digests)
			solve(outputs, true)
			outputs[0] = wireFixtureToken(257, 1000, 10)
			solve(outputs, false)
		})
	}
}

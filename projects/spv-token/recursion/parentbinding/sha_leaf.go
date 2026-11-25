package parentbinding

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const SHA256BlockIndexBits = 32

// SHA256Leaf proves a fixed number of complete private SHA-256 blocks. Start
// and End are each two big-endian uint128 limbs, followed by the starting
// block index in the public witness. The first segment starts from the SHA
// IV. A caller links other starts to authenticated predecessor segments.
type SHA256Leaf struct {
	Start      [2]frontend.Variable `gnark:",public"`
	End        [2]frontend.Variable `gnark:",public"`
	StartBlock frontend.Variable    `gnark:",public"`
	Blocks     []frontend.Variable
}

func (c *SHA256Leaf) Define(api frontend.API) error {
	if len(c.Blocks) == 0 || len(c.Blocks)%blockSize != 0 {
		return fmt.Errorf("expected one or more complete private SHA-256 blocks")
	}
	api.ToBinary(c.StartBlock, SHA256BlockIndexBits)
	if lastOffset := len(c.Blocks)/blockSize - 1; lastOffset != 0 {
		api.ToBinary(api.Add(c.StartBlock, lastOffset), SHA256BlockIndexBits)
	}
	var initial [stateSize]byte
	for i, word := range initialState {
		binary.BigEndian.PutUint32(initial[4*i:], word)
	}
	isFirst := api.IsZero(c.StartBlock)
	for i, limb := range sha256StateLimbs(initial) {
		api.AssertIsEqual(api.Mul(isFirst, api.Sub(c.Start[i], limb)), 0)
	}
	checkpoint := Checkpoint{
		Blocks: c.Blocks,
		Start:  sha256StateBytes(api, c.Start),
		End:    sha256StateBytes(api, c.End),
	}
	return checkpoint.Define(api)
}

func sha256StateBytes(api frontend.API, limbs [2]frontend.Variable) (state [stateSize]frontend.Variable) {
	const limbBytes = stateSize / 2
	for i, limb := range limbs {
		bits := api.ToBinary(limb, 8*limbBytes)
		for j := 0; j < limbBytes; j++ {
			offset := 8 * (limbBytes - j - 1)
			state[i*limbBytes+j] = api.FromBinary(bits[offset : offset+8]...)
		}
	}
	return state
}

func sha256StateLimbs(state [stateSize]byte) [2]*big.Int {
	return [2]*big.Int{
		new(big.Int).SetBytes(state[:stateSize/2]),
		new(big.Int).SetBytes(state[stateSize/2:]),
	}
}

// AssignSHA256Leaf encodes a segment witness for a circuit compiled with the
// same number of complete blocks. The relation treats the bytes as supplied
// and leaves padding and transaction parsing to its caller.
func AssignSHA256Leaf(startBlock uint32, blocks []byte, start, end [stateSize]byte) (*SHA256Leaf, error) {
	if len(blocks) == 0 || len(blocks)%blockSize != 0 {
		return nil, fmt.Errorf("expected one or more complete private SHA-256 blocks")
	}
	startLimbs, endLimbs := sha256StateLimbs(start), sha256StateLimbs(end)
	witness := &SHA256Leaf{
		Start:      [2]frontend.Variable{startLimbs[0], startLimbs[1]},
		End:        [2]frontend.Variable{endLimbs[0], endLimbs[1]},
		StartBlock: startBlock,
		Blocks:     make([]frontend.Variable, len(blocks)),
	}
	for i, value := range blocks {
		witness.Blocks[i] = value
	}
	return witness, nil
}

// Package parentbinding measures the SHA-256 compression relation as one
// component of a separate parent-binding proof.
package parentbinding

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/sha2"
)

const blockSize = 64
const stateSize = 32

var initialState = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// Checkpoint proves compression of complete public blocks from a public start
// state to a public end state. The caller supplies any padding as block bytes.
// A checkpoint alone has no transaction, position, length, or padding claim.
type Checkpoint struct {
	Blocks []frontend.Variable          `gnark:",public"`
	Start  [stateSize]frontend.Variable `gnark:",public"`
	End    [stateSize]frontend.Variable `gnark:",public"`
	FromIV bool                         `gnark:"-"`
}

func (c *Checkpoint) Define(api frontend.API) error {
	if len(c.Blocks) == 0 || len(c.Blocks)%blockSize != 0 {
		return fmt.Errorf("expected one or more complete SHA-256 blocks")
	}
	words, err := uints.New[uints.U32](api)
	if err != nil {
		return fmt.Errorf("initialize SHA-256 words: %w", err)
	}
	byteAPI, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("initialize SHA-256 bytes: %w", err)
	}

	var state [8]uints.U32
	for i := range state {
		var group [4]uints.U8
		for j := range group {
			group[j] = byteAPI.ValueOf(c.Start[4*i+j])
		}
		if c.FromIV {
			state[i] = uints.NewU32(initialState[i])
			for j, want := range words.UnpackMSB(state[i]) {
				byteAPI.AssertIsEqual(group[j], want)
			}
		} else {
			state[i] = words.PackMSB(group[:]...)
		}
	}
	for offset := 0; offset < len(c.Blocks); offset += blockSize {
		var block [blockSize]uints.U8
		for i := range block {
			block[i] = byteAPI.ValueOf(c.Blocks[offset+i])
		}
		state = sha2.Permute(words, state, block)
	}
	for i, word := range state {
		for j, actual := range words.UnpackMSB(word) {
			api.AssertIsEqual(actual.Val, c.End[4*i+j])
		}
	}
	return nil
}

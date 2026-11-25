// Package inventoryorigin relates a four-leaf, externally authenticated issuance
// list to a reusable Merkle inventory. The caller authenticates the list anchor.
package inventoryorigin

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/freeze"
)

const StatementSize = 65
const OpeningSize = 132

type Circuit struct {
	Public   [2]frontend.Variable `gnark:",public"`
	Approved [4][32]frontend.Variable
	Order    [4]frontend.Variable
}

func pair(api frontend.API, left, right []frontend.Variable) []frontend.Variable {
	payload := append([]frontend.Variable{1}, left...)
	return freeze.SHA256dBytes(api, append(payload, right...))
}

func (c *Circuit) Define(api frontend.API) error {
	approved := []frontend.Variable{4}
	for _, item := range c.Approved {
		approved = append(approved, item[:]...)
	}
	anchor := freeze.SHA256dBytes(api, approved)
	var leaves [4][32]frontend.Variable
	for i, slot := range c.Order {
		bits := api.ToBinary(slot, 2)
		for j := 0; j < i; j++ {
			api.AssertIsDifferent(slot, c.Order[j])
		}
		for j := range leaves[i] {
			leaves[i][j] = api.Lookup2(bits[0], bits[1], c.Approved[0][j], c.Approved[1][j], c.Approved[2][j], c.Approved[3][j])
		}
	}
	left := pair(api, leaves[0][:], leaves[1][:])
	right := pair(api, leaves[2][:], leaves[3][:])
	root := pair(api, left, right)
	freeze.AssertSHA256dStatement(api, "\x03", append(anchor, root...), c.Public)
	return nil
}

type Statement [StatementSize]byte

func (s Statement) Encode() []byte { return s[:] }
func (s Statement) Digest() [32]byte {
	first := sha256.Sum256(s[:])
	return sha256.Sum256(first[:])
}
func (s Statement) Limbs() [2]*big.Int {
	digest := s.Digest()
	return [2]*big.Int{new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:])}
}

// Decode validates wire widths and leaves all proof relations to the circuit.
func Decode(raw, opening []byte) (Statement, *Circuit, error) {
	var s Statement
	if len(raw) != StatementSize || raw[0] != 3 || len(opening) != OpeningSize {
		return s, nil, fmt.Errorf("expected 65-byte inventory origin statement and 132-byte opening")
	}
	copy(s[:], raw)
	limits := s.Limbs()
	c := &Circuit{Public: [2]frontend.Variable{limits[0], limits[1]}}
	for i := range c.Approved {
		for j := range c.Approved[i] {
			c.Approved[i][j] = opening[i*32+j]
		}
		c.Order[i] = opening[128+i]
	}
	return s, c, nil
}

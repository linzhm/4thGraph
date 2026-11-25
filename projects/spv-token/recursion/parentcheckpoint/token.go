package parentcheckpoint

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/freeze"
)

const (
	TokenParentSize        = 3433
	TokenProcessedLength   = 1856
	TokenOutputCountOffset = 1871
	TokenOutputCount       = 1

	tokenMetadata = TokenOutputCountOffset + 1 + 8 + 3
	tokenMarker   = "\x12BSV/CCTP/token/v2\x00\x4a"
	tokenQuantity = tokenMetadata + len(tokenMarker) + 32
	tokenOwner    = tokenQuantity + 8
	tokenFlag     = tokenOwner + 33
)

// TokenCircuit authenticates the raw fixed-shape legacy CCTP token parent.
// The receiver checks the exact selected output policy from the proven suffix.
type TokenCircuit struct {
	Public [2]frontend.Variable `gnark:",public"`
	Parent [TokenParentSize]frontend.Variable
}

func (c *TokenCircuit) Define(api frontend.API) error {
	// Two inputs, with canonical CompactSizes for the 1,782-byte first
	// scriptSig and the empty sponsor scriptSig. These fix the output offset.
	api.AssertIsEqual(c.Parent[4], 2)
	api.AssertIsEqual(c.Parent[41], 0xfd)
	api.AssertIsEqual(c.Parent[42], 0xf6)
	api.AssertIsEqual(c.Parent[43], 0x06)
	api.AssertIsEqual(c.Parent[TokenOutputCountOffset-5], 0)
	api.AssertIsEqual(c.Parent[TokenOutputCountOffset], TokenOutputCount)

	// One 1,546-byte locking script, followed immediately by locktime.
	output := TokenOutputCountOffset + 1
	api.AssertIsEqual(c.Parent[output+8], 0xfd)
	api.AssertIsEqual(c.Parent[output+9], 0x0a)
	api.AssertIsEqual(c.Parent[output+10], 0x06)
	const maxMoney = 21_000_000 * 100_000_000
	amount := parentUint64(api, c.Parent[output:output+8])
	api.AssertIsDifferent(amount, 0)
	api.ToBinary(api.Sub(maxMoney, amount), bits.Len64(maxMoney))
	for i, value := range []byte(tokenMarker) {
		api.AssertIsEqual(c.Parent[tokenMetadata+i], value)
	}
	api.AssertIsDifferent(parentUint64(api, c.Parent[tokenQuantity:tokenOwner]), 0)
	api.AssertIsEqual(api.Mul(api.Sub(c.Parent[tokenOwner], 2), api.Sub(c.Parent[tokenOwner], 3)), 0)
	api.AssertIsEqual(c.Parent[tokenFlag], 0)

	tx := c.Parent[:]
	midstate, txid := freeze.SHA256dAtCheckpoint(api, tx, TokenProcessedLength)
	payload := make([]frontend.Variable, 0, PayloadSize)
	payload = append(payload, txid...)
	payload = append(payload, midstate...)
	lengthAndCounts := binary.LittleEndian.AppendUint64(nil, TokenProcessedLength)
	lengthAndCounts = binary.LittleEndian.AppendUint32(lengthAndCounts, TokenOutputCountOffset)
	lengthAndCounts = binary.LittleEndian.AppendUint32(lengthAndCounts, TokenOutputCount)
	for _, value := range lengthAndCounts {
		payload = append(payload, value)
	}
	payload = append(payload, freeze.SHA256dBytes(api, tx[TokenProcessedLength:])...)
	// The authenticated suffix already commits the entire serialized TxOut.
	// The final word is reserved zero in this test key's statement profile.
	for i := 0; i < 32; i++ {
		payload = append(payload, 0)
	}
	freeze.AssertSHA256dStatement(api, Domain, payload, c.Public)
	return nil
}

func parentUint64(api frontend.API, raw []frontend.Variable) frontend.Variable {
	value := frontend.Variable(0)
	for i := len(raw) - 1; i >= 0; i-- {
		value = api.Add(api.Mul(value, 256), raw[i])
	}
	return value
}

func (s Statement) TokenAssignment(raw []byte) (*TokenCircuit, error) {
	if len(raw) != TokenParentSize {
		return nil, fmt.Errorf("expected %d-byte token parent transaction", TokenParentSize)
	}
	limbs := s.Limbs()
	circuit := &TokenCircuit{Public: [2]frontend.Variable{limbs[0], limbs[1]}}
	for i, value := range raw {
		circuit.Parent[i] = value
	}
	return circuit, nil
}

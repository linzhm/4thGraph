// Package conservation implements the circuit boundary for a two-input,
// two-output CCTP transfer authenticated by BSV Script.
package conservation

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/freeze"
)

const Domain = "BSV/CCTP/conservation/v1\x00"
const ContextSize = 104
const PayloadSize = ContextSize + 4*freeze.StateSize
const EncodedSize = len(Domain) + PayloadSize

// Statement starts with the actual version, hashPrevouts, hashSequence,
// SHA256d(serialized vout 0 || serialized vout 1), and locktime. The next
// records are prior vin 2, prior vin 3, next vout 0, and next vout 1, in
// that order. Each is sats LE64, asset[32], quantity LE64, owner[33],
// frozen[1], and policy[32]. Policy identifies the authenticated locking
// template independently of mutable token metadata.
type Statement [PayloadSize]byte

func ParseStatement(raw []byte) (Statement, error) {
	var statement Statement
	if len(raw) != EncodedSize || !bytes.HasPrefix(raw, []byte(Domain)) {
		return statement, fmt.Errorf("expected %d-byte versioned conservation statement", EncodedSize)
	}
	copy(statement[:], raw[len(Domain):])
	return statement, nil
}

func (s Statement) Encode() []byte {
	return append([]byte(Domain), s[:]...)
}

func (s Statement) Digest() [32]byte {
	first := sha256.Sum256(s.Encode())
	return sha256.Sum256(first[:])
}

func (s Statement) Limbs() [2]*big.Int {
	digest := s.Digest()
	return [2]*big.Int{new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:])}
}

func (s Statement) Assignment() *Circuit {
	limbs := s.Limbs()
	circuit := &Circuit{Public: [2]frontend.Variable{limbs[0], limbs[1]}}
	for i, value := range s {
		circuit.Payload[i] = value
	}
	return circuit
}

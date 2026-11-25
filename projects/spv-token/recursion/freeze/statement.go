// Package freeze binds an administrative successor proof to fields authenticated
// by the native BSV covenant and its separate issuer authorization.
package freeze

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const Domain = "BSV/CCTP/freeze-transition/v1\x00"

const (
	OutpointSize   = 36
	IndexSize      = 4
	ContextSize    = 32
	StateSize      = 114
	PairOffset     = OutpointSize + IndexSize + ContextSize
	PayloadSize    = PairOffset + 2*StateSize
	EncodedSize    = len(Domain) + PayloadSize
	QuantityOffset = 8 + 32
	OwnerOffset    = QuantityOffset + 8
	FrozenOffset   = OwnerOffset + 33
)

// Statement stores the literal wire payload after the domain. It starts with
// the actual input outpoint, the paired index (u32 LE), and the digest of the
// actual token input's ForkID SINGLE preimage. It ends with ordered prior and
// successor states.
//
// Each state encodes sats[8 LE], asset[32], quantity[8 LE], owner[33],
// frozen[1], and policy[32]. Policy is SHA-256 of the canonical serialized
// script field (CompactSize and locking script) with the frozen byte set to
// zero. The caller derives these fields from the exact authenticated outputs.
type Statement [PayloadSize]byte

func ParseStatement(raw []byte) (Statement, error) {
	var statement Statement
	if len(raw) != EncodedSize || !bytes.HasPrefix(raw, []byte(Domain)) {
		return statement, fmt.Errorf("expected %d-byte versioned freeze statement", EncodedSize)
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
	c := &Circuit{Public: [2]frontend.Variable{limbs[0], limbs[1]}}
	for i, value := range s {
		c.Payload[i] = value
	}
	return c
}

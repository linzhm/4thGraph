// Package parentcheckpoint proves SHA-256 checkpoints and output boundaries
// for bounded test parent transactions.
package parentcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const Domain = "BSV/CCTP/parent-checkpoint/v1\x00"
const PayloadSize = 144
const EncodedSize = len(Domain) + PayloadSize

const (
	ParentSize        = 332
	ProcessedLength   = 256
	OutputCountOffset = 307
	OutputCount       = 2
	OutputStart       = OutputCountOffset + 1
	OutputEnd         = ParentSize - 4
)

// Statement contains txid wire bytes, the 32-byte checkpoint in SHA word
// order, processed length LE64, output count offset LE32, output count LE32,
// SHA256d(suffix), and a profile-dependent output commitment. The short parent
// uses SHA256d(serialized output vector). The Token parent reserves zero.
type Statement [PayloadSize]byte

func ParseStatement(raw []byte) (Statement, error) {
	var statement Statement
	if len(raw) != EncodedSize || !bytes.HasPrefix(raw, []byte(Domain)) {
		return statement, fmt.Errorf("expected %d-byte versioned parent checkpoint statement", EncodedSize)
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

func (s Statement) Assignment(raw []byte) (*Circuit, error) {
	if len(raw) != ParentSize {
		return nil, fmt.Errorf("expected %d-byte parent transaction", ParentSize)
	}
	limbs := s.Limbs()
	circuit := &Circuit{Public: [2]frontend.Variable{limbs[0], limbs[1]}}
	for i, value := range raw {
		circuit.Parent[i] = value
	}
	return circuit, nil
}

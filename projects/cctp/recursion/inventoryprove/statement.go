package inventoryprove

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type Statement [PaymentSize]byte

func (s Statement) Encode() []byte { return s[:] }
func (s Statement) Digest() [32]byte {
	first := sha256.Sum256(s[:])
	return sha256.Sum256(first[:])
}
func (s Statement) Limbs() [2]*big.Int {
	digest := s.Digest()
	return [2]*big.Int{new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:])}
}

// Decode reads the public payment (including tag 02) and exactly two private
// openings in vin order: state50, leaf index u8, two sibling hashes bottom-up.
func Decode(payment, openings []byte) (Statement, *Circuit, error) {
	var s Statement
	if len(payment) != PaymentSize || payment[0] != 2 || len(openings) != WitnessSize {
		return s, nil, fmt.Errorf("expected tag 02, %d payment bytes and %d opening bytes", PaymentSize, WitnessSize)
	}
	copy(s[:], payment)
	limbs := s.Limbs()
	c := &Circuit{Public: [2]frontend.Variable{limbs[0], limbs[1]}}
	for i, value := range s[1:] {
		c.Payload[i] = value
	}
	for i := range c.Openings {
		part := openings[i*OpeningSize : (i+1)*OpeningSize]
		o := &c.Openings[i]
		for j := range o.State {
			o.State[j] = part[j]
		}
		o.Index = part[StateSize]
		for j := range o.Siblings {
			for k := range o.Siblings[j] {
				o.Siblings[j][k] = part[StateSize+1+32*j+k]
			}
		}
	}
	return s, c, nil
}

package freeze

import "github.com/consensys/gnark/frontend"

// PlainCircuit proves the same freeze statement using a bitwise SHA-256
// implementation suitable for Groth16 without a BSB22 commitment.
type PlainCircuit Circuit

func (s Statement) PlainAssignment() *PlainCircuit {
	return (*PlainCircuit)(s.Assignment())
}

func (c *PlainCircuit) Define(api frontend.API) error {
	payload := make([]shaOctet, 0, len(Domain)+len(c.Payload))
	for _, value := range []byte(Domain) {
		payload = append(payload, octetBits(value))
	}
	for _, value := range c.Payload {
		payload = append(payload, shaOctet(api.ToBinary(value, 8)))
	}
	constrainTransition(api, c.Payload[:])

	digest := sha256Bits(api, sha256Bits(api, payload))
	for i, expected := range c.Public {
		limb := frontend.Variable(0)
		for _, octet := range digest[i*16 : (i+1)*16] {
			limb = api.Add(api.Mul(limb, 256), api.FromBinary(octet[:]...))
		}
		api.AssertIsEqual(expected, limb)
	}
	return nil
}

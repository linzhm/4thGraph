package conservation

import (
	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
)

// Circuit proves the rules over four ordered, BSV-authenticated token states.
// The binding to actual inputs and outputs and the owner signatures are
// checked by the surrounding BSV locks.
type Circuit struct {
	Public  [2]frontend.Variable `gnark:",public"`
	Payload [PayloadSize]frontend.Variable
}

func littleEndian(api frontend.API, values []frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for i := len(values) - 1; i >= 0; i-- {
		result = api.Add(api.Mul(result, 256), values[i])
	}
	return result
}

func (c *Circuit) Define(api frontend.API) error {
	records := c.Payload[ContextSize:]
	reference := records[:freeze.StateSize]
	var quantities, satoshis [4]frontend.Variable
	for i := range quantities {
		state := records[i*freeze.StateSize : (i+1)*freeze.StateSize]
		quantity := littleEndian(api, state[freeze.QuantityOffset:freeze.OwnerOffset])
		sats := littleEndian(api, state[:8])
		api.AssertIsDifferent(quantity, 0)
		api.AssertIsDifferent(sats, 0)
		api.AssertIsEqual(state[freeze.FrozenOffset], 0)
		ownerPrefix := state[freeze.OwnerOffset]
		api.AssertIsEqual(api.Mul(api.Sub(ownerPrefix, 2), api.Sub(ownerPrefix, 3)), 0)
		if i > 0 {
			for j := 8; j < freeze.QuantityOffset; j++ {
				api.AssertIsEqual(state[j], reference[j])
			}
			for j := freeze.FrozenOffset + 1; j < freeze.StateSize; j++ {
				api.AssertIsEqual(state[j], reference[j])
			}
		}
		quantities[i], satoshis[i] = quantity, sats
	}

	inputQuantity := api.Add(quantities[0], quantities[1])
	api.AssertIsEqual(inputQuantity, api.Add(quantities[2], quantities[3]))
	// Each operand is a uint64 and the BLS scalar field exceeds uint65.
	// This decomposition rules out overflow in the conserved total.
	api.ToBinary(inputQuantity, 64)
	api.AssertIsEqual(api.Add(satoshis[0], satoshis[1]), api.Add(satoshis[2], satoshis[3]))
	freeze.AssertSHA256dStatement(api, Domain, c.Payload[:], c.Public)
	return nil
}

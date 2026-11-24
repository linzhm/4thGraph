package conservation

import (
	"fmt"

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

// AssertDistinctOutpoints rejects repeated authenticated vin outpoints. Each
// byte must be constrained by the caller's transaction context or its parser.
func AssertDistinctOutpoints(api frontend.API, outpoints [][freeze.OutpointSize]frontend.Variable) {
	const half = freeze.OutpointSize / 2
	packed := make([][2]frontend.Variable, len(outpoints))
	for i, outpoint := range outpoints {
		packed[i] = [2]frontend.Variable{littleEndian(api, outpoint[:half]), littleEndian(api, outpoint[half:])}
	}
	for i, left := range packed {
		for _, right := range packed[i+1:] {
			sameLow := api.IsZero(api.Sub(left[0], right[0]))
			sameHigh := api.IsZero(api.Sub(left[1], right[1]))
			api.AssertIsEqual(api.Mul(sameLow, sameHigh), 0)
		}
	}
}

func (c *Circuit) Define(api frontend.API) error {
	if err := Assert2x2(api, c.Payload[ContextSize:]); err != nil {
		return err
	}
	freeze.AssertSHA256dStatement(api, Domain, c.Payload[:], c.Public)
	return nil
}

// Assert2x2 enforces the regular transfer rules over two prior and two
// successor state records in transaction order. The caller must constrain
// each record byte and authenticate it against the corresponding actual TxOut.
func Assert2x2(api frontend.API, records []frontend.Variable) error {
	if len(records) != 4*freeze.StateSize {
		return fmt.Errorf("expected four ordered CCTP state records")
	}
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
	return nil
}

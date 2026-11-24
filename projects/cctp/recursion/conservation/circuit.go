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
	return AssertTransfer(api, records, 2)
}

// AssertTransfer checks positive active states with a shared asset and policy.
// Input records precede output records. The caller authenticates every record
// and its position against the corresponding actual TxOut and constrains all
// bytes. Token quantities and satoshis are conserved independently.
func AssertTransfer(api frontend.API, records []frontend.Variable, inputCount int) error {
	count := len(records) / freeze.StateSize
	if len(records)%freeze.StateSize != 0 || inputCount < 1 || inputCount >= count {
		return fmt.Errorf("expected nonempty ordered transfer input and output state records")
	}
	reference := records[:freeze.StateSize]
	quantities := make([]frontend.Variable, count)
	satoshis := make([]frontend.Variable, count)
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

	sum := func(values []frontend.Variable) frontend.Variable {
		total := values[0]
		for _, value := range values[1:] {
			total = api.Add(total, value)
		}
		return total
	}
	inputQuantity := sum(quantities[:inputCount])
	api.AssertIsEqual(inputQuantity, sum(quantities[inputCount:]))
	// The byte-constrained uint64 operands cannot wrap the proving field.
	// Restrict the conserved quantity to the protocol's uint64 range.
	api.ToBinary(inputQuantity, 64)
	api.AssertIsEqual(sum(satoshis[:inputCount]), sum(satoshis[inputCount:]))
	return nil
}

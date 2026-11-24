package freeze

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// Circuit proves a single paired freeze or unfreeze transition. BSV Script
// authenticates the transaction, actual outpoint, output index and fields,
// then derives the same two public limbs from those fields.
type Circuit struct {
	Public  [2]frontend.Variable `gnark:",public"`
	Payload [PayloadSize]frontend.Variable
}

func uint128(api frontend.API, data []uints.U8) frontend.Variable {
	n := frontend.Variable(0)
	for _, item := range data {
		n = api.Add(api.Mul(n, 256), item.Val)
	}
	return n
}

func (c *Circuit) Define(api frontend.API) error {
	byteAPI, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("initialize freeze byte constraints: %w", err)
	}
	var payload [PayloadSize]uints.U8
	for i, value := range c.Payload {
		payload[i] = byteAPI.ValueOf(value)
	}
	constrainTransition(api, c.Payload[:])

	first, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("initialize first freeze hash: %w", err)
	}
	second, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("initialize second freeze hash: %w", err)
	}
	first.Write(uints.NewU8Array([]byte(Domain)))
	first.Write(payload[:])
	second.Write(first.Sum())
	digest := second.Sum()
	api.AssertIsEqual(c.Public[0], uint128(api, digest[:16]))
	api.AssertIsEqual(c.Public[1], uint128(api, digest[16:]))
	return nil
}

func constrainTransition(api frontend.API, payload []frontend.Variable) {
	prior, successor := payload[PairOffset:PairOffset+StateSize], payload[PairOffset+StateSize:]
	for i, item := range prior {
		if i != FrozenOffset {
			api.AssertIsEqual(item, successor[i])
		}
	}
	priorFlag, successorFlag := prior[FrozenOffset], successor[FrozenOffset]
	api.AssertIsBoolean(priorFlag)
	api.AssertIsBoolean(successorFlag)
	api.AssertIsEqual(api.Add(priorFlag, successorFlag), 1)

	quantity := frontend.Variable(0)
	for i := OwnerOffset - 1; i >= QuantityOffset; i-- {
		quantity = api.Add(api.Mul(quantity, 256), prior[i])
	}
	api.AssertIsDifferent(quantity, 0)
	ownerPrefix := prior[OwnerOffset]
	api.AssertIsEqual(api.Mul(api.Sub(ownerPrefix, 2), api.Sub(ownerPrefix, 3)), 0)
}

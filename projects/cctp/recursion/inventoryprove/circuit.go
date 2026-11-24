// Package inventoryprove implements the payment half of the four-leaf wallet
// inventory experiment. The BSV verifier separately authenticates the root
// certificate and derives the public payment statement from the actual spend.
package inventoryprove

import (
	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/conservation"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
)

const (
	StateSize   = 50
	PaymentSize = 1 + 32 + 32 + 2*freeze.OutpointSize + 2*StateSize
	OpeningSize = StateSize + 1 + 2*32
	WitnessSize = 2 * OpeningSize
)

type Opening struct {
	State    [StateSize]frontend.Variable
	Index    frontend.Variable
	Siblings [2][32]frontend.Variable
}

type Circuit struct {
	Public   [2]frontend.Variable `gnark:",public"`
	Payload  [PaymentSize - 1]frontend.Variable
	Openings [2]Opening
}

// transferState expands the compact record into the conservation gadget's
// encoding. One scope already commits to the asset, Genesis and policy.
func transferState(scope, state []frontend.Variable) []frontend.Variable {
	record := append([]frontend.Variable{}, state[8:16]...) // sats
	record = append(record, scope...)
	record = append(record, state[:8]...)
	record = append(record, state[16:]...)
	return append(record, scope...)
}

func (c *Circuit) Define(api frontend.API) error {
	scope, root := c.Payload[:32], c.Payload[32:64]
	var points [2][freeze.OutpointSize]frontend.Variable
	var records []frontend.Variable
	for i := range c.Openings {
		start := 64 + i*freeze.OutpointSize
		copy(points[i][:], c.Payload[start:start+freeze.OutpointSize])
		opening := &c.Openings[i]
		leaf := append([]frontend.Variable{0}, scope...)
		leaf = append(leaf, points[i][:]...)
		leaf = append(leaf, opening.State[:]...)
		digest := freeze.SHA256dBytes(api, leaf)
		directions := api.ToBinary(opening.Index, len(opening.Siblings))
		for level, sibling := range opening.Siblings {
			node := make([]frontend.Variable, 65)
			node[0] = 1
			for j, current := range digest {
				left := api.Select(directions[level], sibling[j], current)
				node[1+j] = left
				node[33+j] = api.Sub(api.Add(sibling[j], current), left)
			}
			digest = freeze.SHA256dBytes(api, node)
		}
		for j, value := range digest {
			api.AssertIsEqual(value, root[j])
		}
		records = append(records, transferState(scope, opening.State[:])...)
	}
	conservation.AssertDistinctOutpoints(api, points[:])
	api.AssertIsDifferent(c.Openings[0].Index, c.Openings[1].Index)
	for i := 0; i < 2; i++ {
		start := 64 + 2*freeze.OutpointSize + i*StateSize
		records = append(records, transferState(scope, c.Payload[start:start+StateSize])...)
	}
	if err := conservation.Assert2x2(api, records); err != nil {
		return err
	}
	freeze.AssertSHA256dStatement(api, "\x02", c.Payload[:], c.Public)
	return nil
}

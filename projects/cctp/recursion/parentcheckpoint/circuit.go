package parentcheckpoint

import (
	"encoding/binary"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
)

// Circuit derives its public digest from one fixed parent shape. The
// surrounding BSV receiver authenticates txid against the actual outpoint.
type Circuit struct {
	Public [2]frontend.Variable `gnark:",public"`
	Parent [ParentSize]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	// Fixed structure: version, one input, outpoint, canonical CompactSize
	// 259, PUSHDATA2(256), 256 payload bytes, sequence, and two TxOuts.
	api.AssertIsEqual(c.Parent[4], 1)
	for i, value := range []byte{0xfd, 0x03, 0x01, 0x4d, 0x00, 0x01} {
		api.AssertIsEqual(c.Parent[41+i], value)
	}
	api.AssertIsEqual(c.Parent[OutputCountOffset], OutputCount)
	const maxMoney = 21_000_000 * 100_000_000
	for cursor := OutputStart; cursor < OutputEnd; cursor += 10 {
		api.AssertIsEqual(c.Parent[cursor+8], 1)
		sats := frontend.Variable(0)
		for i := 7; i >= 0; i-- {
			sats = api.Add(api.Mul(sats, 256), c.Parent[cursor+i])
		}
		api.ToBinary(api.Sub(maxMoney, sats), bits.Len64(maxMoney))
	}

	tx := c.Parent[:]
	midstate, txid := freeze.SHA256dAtCheckpoint(api, tx, ProcessedLength)
	payload := make([]frontend.Variable, 0, PayloadSize)
	payload = append(payload, txid...)
	payload = append(payload, midstate...)
	lengthAndCounts := binary.LittleEndian.AppendUint64(nil, ProcessedLength)
	lengthAndCounts = binary.LittleEndian.AppendUint32(lengthAndCounts, OutputCountOffset)
	lengthAndCounts = binary.LittleEndian.AppendUint32(lengthAndCounts, OutputCount)
	for _, value := range lengthAndCounts {
		payload = append(payload, value)
	}
	payload = append(payload, freeze.SHA256dBytes(api, tx[ProcessedLength:])...)
	payload = append(payload, freeze.SHA256dBytes(api, tx[OutputStart:OutputEnd])...)
	freeze.AssertSHA256dStatement(api, Domain, payload, c.Public)
	return nil
}

package parentbinding

import (
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
)

const projectionLimbBytes = 16

// SHA256FieldSpan describes a fixed range relative to the start of a segment.
type SHA256FieldSpan struct {
	Offset int
	Length int
}

// SHA256ProjectionLeaf opens selected bytes from the same private segment that
// SHA256Leaf uses for compression. The public witness is the five SHA256Leaf
// scalars followed by the selected bytes packed in consecutive big-endian
// uint128 limbs. The final limb uses its actual byte length without padding.
// A consumer must match the public start block and this circuit's fixed span
// layout to the expected transaction offsets.
type SHA256ProjectionLeaf struct {
	Segment    SHA256Leaf
	Projection []frontend.Variable `gnark:",public"`
	spans      []SHA256FieldSpan   `gnark:"-"`
}

func NewSHA256ProjectionLeaf(blockCount int, spans []SHA256FieldSpan) (*SHA256ProjectionLeaf, error) {
	if blockCount < 1 || blockCount > math.MaxInt/blockSize {
		return nil, fmt.Errorf("expected one or more complete SHA-256 blocks")
	}
	width := blockCount * blockSize
	byteCount, err := projectionSize(spans, width)
	if err != nil {
		return nil, err
	}
	return &SHA256ProjectionLeaf{
		Segment:    SHA256Leaf{Blocks: make([]frontend.Variable, width)},
		Projection: make([]frontend.Variable, projectionLimbs(byteCount)),
		spans:      slices.Clone(spans),
	}, nil
}

func (c *SHA256ProjectionLeaf) Define(api frontend.API) error {
	byteCount, err := projectionSize(c.spans, len(c.Segment.Blocks))
	if err != nil {
		return err
	}
	if len(c.Projection) != projectionLimbs(byteCount) {
		return fmt.Errorf("incorrect number of public projection limbs")
	}
	if err := c.Segment.Define(api); err != nil {
		return err
	}
	selected := projectBytes(c.Segment.Blocks, c.spans, byteCount)
	for i, limb := range c.Projection {
		start := i * projectionLimbBytes
		end := min(start+projectionLimbBytes, byteCount)
		var packed frontend.Variable = 0
		for _, value := range selected[start:end] {
			packed = api.Add(api.Mul(packed, 256), value)
		}
		api.AssertIsEqual(packed, limb)
	}
	return nil
}

// Assignment builds a witness with the block count and fixed spans of c.
func (c *SHA256ProjectionLeaf) Assignment(startBlock uint32, blocks []byte, start, end [stateSize]byte) (*SHA256ProjectionLeaf, error) {
	if len(blocks) != len(c.Segment.Blocks) {
		return nil, fmt.Errorf("expected %d private segment bytes", len(c.Segment.Blocks))
	}
	byteCount, err := projectionSize(c.spans, len(blocks))
	if err != nil {
		return nil, err
	}
	segment, err := AssignSHA256Leaf(startBlock, blocks, start, end)
	if err != nil {
		return nil, err
	}
	selected := projectBytes(blocks, c.spans, byteCount)
	limbs := make([]frontend.Variable, projectionLimbs(byteCount))
	for i := range limbs {
		start := i * projectionLimbBytes
		limbs[i] = new(big.Int).SetBytes(selected[start:min(start+projectionLimbBytes, byteCount)])
	}
	return &SHA256ProjectionLeaf{Segment: *segment, Projection: limbs, spans: c.spans}, nil
}

func projectionSize(spans []SHA256FieldSpan, width int) (int, error) {
	if len(spans) == 0 {
		return 0, fmt.Errorf("expected at least one SHA-256 projection span")
	}
	var precedingEnd, size int
	for _, span := range spans {
		if span.Offset < precedingEnd || span.Length <= 0 || span.Offset > width || span.Length > width-span.Offset {
			return 0, fmt.Errorf("SHA-256 projection spans must be nonempty, ordered, disjoint and inside the segment")
		}
		precedingEnd = span.Offset + span.Length
		size += span.Length
	}
	return size, nil
}

func projectionLimbs(byteCount int) int {
	return (byteCount + projectionLimbBytes - 1) / projectionLimbBytes
}

func projectBytes[T any](blocks []T, spans []SHA256FieldSpan, byteCount int) []T {
	selected := make([]T, 0, byteCount)
	for _, span := range spans {
		selected = append(selected, blocks[span.Offset:span.Offset+span.Length]...)
	}
	return selected
}

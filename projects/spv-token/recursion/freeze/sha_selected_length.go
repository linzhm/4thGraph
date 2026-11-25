package freeze

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/consensys/gnark/frontend"
)

// SHA256dAtSelectedLength hashes exactly one compile-time prefix length of the
// input. Selectors are constrained to be one-hot. The input buffer has the
// largest allowed width, and bytes after the selected prefix must be zero.
// The first hash shares one compression chain and uses no lookup commitments.
func SHA256dAtSelectedLength(api frontend.API, message []frontend.Variable, lengths []int,
	selectors []frontend.Variable) ([]frontend.Variable, error) {
	const blockSize = 64
	if len(lengths) == 0 || len(lengths) != len(selectors) {
		return nil, fmt.Errorf("expected a selector for each SHA-256 length")
	}
	if uint64(len(message)) > math.MaxUint64/8 || len(message) > math.MaxInt-blockSize-8 {
		return nil, fmt.Errorf("SHA-256 buffer is too large")
	}
	byLength := make(map[int]frontend.Variable)
	var ordered []int
	var count frontend.Variable = 0
	for i, length := range lengths {
		if length < 0 || length > len(message) {
			return nil, fmt.Errorf("SHA-256 length %d is outside the input buffer", length)
		}
		selector := selectors[i]
		api.AssertIsBoolean(selector)
		count = api.Add(count, selector)
		if previous, ok := byLength[length]; ok {
			byLength[length] = api.Add(previous, selector)
		} else {
			ordered = append(ordered, length)
			byLength[length] = selector
		}
	}
	api.AssertIsEqual(count, 1)
	slices.Sort(ordered)
	if ordered[len(ordered)-1] != len(message) {
		return nil, fmt.Errorf("SHA-256 buffer must match the largest allowed length")
	}
	if len(ordered) == 1 {
		return SHA256dBytes(api, message), nil
	}

	var ended frontend.Variable = 0
	for i, length := range ordered[:len(ordered)-1] {
		ended = api.Add(ended, byLength[length])
		for _, value := range message[length:ordered[i+1]] {
			api.AssertIsEqual(api.Mul(ended, value), 0)
		}
	}

	paddedSize := func(length int) int { return (length + 9 + blockSize - 1) / blockSize * blockSize }
	padded := make([]shaOctet, paddedSize(len(message)))
	copy(padded, shaInput(api, message))
	for i := len(message); i < len(padded); i++ {
		padded[i] = octetBits(0)
	}
	endSelectors := make(map[int]frontend.Variable)
	for _, length := range ordered {
		selector, end := byLength[length], paddedSize(length)
		// An active padding bit can overlap only a zero input-tail bit.
		padded[length][7] = api.Add(padded[length][7], selector)
		var bitLength [8]byte
		binary.BigEndian.PutUint64(bitLength[:], uint64(length)*8)
		for i, value := range bitLength {
			for bit := range padded[end-8+i] {
				if (value>>bit)&1 != 0 {
					padded[end-8+i][bit] = api.Add(padded[end-8+i][bit], selector)
				}
			}
		}
		if previous, ok := endSelectors[end]; ok {
			endSelectors[end] = api.Add(previous, selector)
		} else {
			endSelectors[end] = selector
		}
	}

	var state [8]shaWord
	for i, iv := range shaIV {
		state[i] = wordBits(iv)
	}
	digest := make([]shaOctet, 32)
	for i := range digest {
		digest[i] = octetBits(0)
	}
	for offset := 0; offset < len(padded); offset += blockSize {
		end := offset + blockSize
		state = compressSHA256(api, state, padded[offset:end])
		if selector, ok := endSelectors[end]; ok {
			for i, octet := range stateOctets(state) {
				for bit := range octet {
					digest[i][bit] = api.Select(selector, octet[bit], digest[i][bit])
				}
			}
		}
	}
	return shaOutput(api, sha256Bits(api, digest)), nil
}

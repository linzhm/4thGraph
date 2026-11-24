package freeze

import (
	"encoding/binary"

	"github.com/consensys/gnark/frontend"
)

func shaInput(api frontend.API, message []frontend.Variable) []shaOctet {
	octets := make([]shaOctet, len(message))
	for i, value := range message {
		octets[i] = shaOctet(api.ToBinary(value, 8))
	}
	return octets
}

func shaOutput(api frontend.API, octets []shaOctet) []frontend.Variable {
	result := make([]frontend.Variable, len(octets))
	for i, value := range octets {
		result[i] = api.FromBinary(value[:]...)
	}
	return result
}

func stateOctets(state [8]shaWord) []shaOctet {
	octets := make([]shaOctet, 32)
	for i, word := range state {
		for j := 0; j < 4; j++ {
			copy(octets[4*i+3-j][:], word[8*j:8*(j+1)])
		}
	}
	return octets
}

// SHA256dBytes constrains the input bytes and returns the double SHA-256
// digest in its standard byte order, with no lookup commitments.
func SHA256dBytes(api frontend.API, message []frontend.Variable) []frontend.Variable {
	raw := shaInput(api, message)
	return shaOutput(api, sha256Bits(api, sha256Bits(api, raw)))
}

// SHA256dAtCheckpoint computes the unpadded SHA-256 state at processed bytes
// and the SHA256d of the entire message. The remaining first-hash blocks
// continue from the computed state and encode the entire message length.
func SHA256dAtCheckpoint(api frontend.API, message []frontend.Variable, processed int) (midstate, digest []frontend.Variable) {
	const blockSize = 64
	if processed < 0 || processed > len(message) || processed%blockSize != 0 {
		panic("SHA-256 checkpoint must be a complete block boundary")
	}
	raw := shaInput(api, message)
	var state [8]shaWord
	for i, iv := range shaIV {
		state[i] = wordBits(iv)
	}
	for offset := 0; offset < processed; offset += blockSize {
		state = compressSHA256(api, state, raw[offset:offset+blockSize])
	}
	midstate = shaOutput(api, stateOctets(state))

	suffix := raw[processed:]
	paddedSize := (len(suffix) + 9 + blockSize - 1) / blockSize * blockSize
	padding := make([]byte, paddedSize-len(suffix))
	padding[0] = 0x80
	binary.BigEndian.PutUint64(padding[len(padding)-8:], uint64(len(message))*8)
	padded := make([]shaOctet, len(suffix), paddedSize)
	copy(padded, suffix)
	for _, value := range padding {
		padded = append(padded, octetBits(value))
	}
	for offset := 0; offset < len(padded); offset += blockSize {
		state = compressSHA256(api, state, padded[offset:offset+blockSize])
	}
	return midstate, shaOutput(api, sha256Bits(api, stateOctets(state)))
}

package freeze

import (
	"encoding/binary"
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

// SHA-256 words and octets use least-significant-bit-first order internally.
type shaOctet [8]frontend.Variable
type shaWord [32]frontend.Variable

var shaIV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var shaK = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func octetBits(value byte) (out shaOctet) {
	for i := range out {
		out[i] = (value >> i) & 1
	}
	return
}

func wordBits(value uint32) (out shaWord) {
	for i := range out {
		out[i] = (value >> i) & 1
	}
	return
}

func rotateRight(value shaWord, n int) (out shaWord) {
	for i := range out {
		out[i] = value[(i+n)%len(out)]
	}
	return
}

func shiftRight(value shaWord, n int) (out shaWord) {
	copied := copy(out[:], value[n:])
	for i := copied; i < len(out); i++ {
		out[i] = 0
	}
	return
}

func xorWords(api frontend.API, a, b, c shaWord) (out shaWord) {
	for i := range out {
		out[i] = api.Xor(api.Xor(a[i], b[i]), c[i])
	}
	return
}

func chooseWord(api frontend.API, x, y, z shaWord) (out shaWord) {
	for i := range out {
		out[i] = api.Select(x[i], y[i], z[i])
	}
	return
}

func majorityWord(api frontend.API, x, y, z shaWord) (out shaWord) {
	for i := range out {
		out[i] = api.Select(api.Xor(x[i], y[i]), z[i], x[i])
	}
	return
}

func addWords(api frontend.API, words ...shaWord) (out shaWord) {
	sum := frontend.Variable(0)
	for _, word := range words {
		sum = api.Add(sum, api.FromBinary(word[:]...))
	}
	// All summands are 32-bit integers. The carry bits are constrained by
	// decomposing the entire sum before discarding them for modulo 2^32.
	width := len(out) + bits.Len(uint(len(words)-1))
	copy(out[:], api.ToBinary(sum, width))
	return
}

func compressSHA256(api frontend.API, state [8]shaWord, block []shaOctet) [8]shaWord {
	var schedule [64]shaWord
	for i := 0; i < 16; i++ {
		for j := 0; j < 4; j++ {
			copy(schedule[i][8*(3-j):], block[4*i+j][:])
		}
	}
	for i := 16; i < len(schedule); i++ {
		x, y := schedule[i-15], schedule[i-2]
		s0 := xorWords(api, rotateRight(x, 7), rotateRight(x, 18), shiftRight(x, 3))
		s1 := xorWords(api, rotateRight(y, 17), rotateRight(y, 19), shiftRight(y, 10))
		schedule[i] = addWords(api, schedule[i-16], s0, schedule[i-7], s1)
	}

	a, b, c, d := state[0], state[1], state[2], state[3]
	e, f, g, h := state[4], state[5], state[6], state[7]
	for i, k := range shaK {
		s1 := xorWords(api, rotateRight(e, 6), rotateRight(e, 11), rotateRight(e, 25))
		t1 := addWords(api, h, s1, chooseWord(api, e, f, g), wordBits(k), schedule[i])
		s0 := xorWords(api, rotateRight(a, 2), rotateRight(a, 13), rotateRight(a, 22))
		t2 := addWords(api, s0, majorityWord(api, a, b, c))
		a, b, c, d, e, f, g, h = addWords(api, t1, t2), a, b, c, addWords(api, d, t1), e, f, g
	}
	for i, word := range [8]shaWord{a, b, c, d, e, f, g, h} {
		state[i] = addWords(api, state[i], word)
	}
	return state
}

// sha256Bits implements the fixed-length SHA-256 pad and compression from
// FIPS 180-4, using boolean and bit decompositions rather than lookup tables.
func sha256Bits(api frontend.API, message []shaOctet) []shaOctet {
	const blockSize = 64
	size := (len(message) + 9 + blockSize - 1) / blockSize * blockSize
	padding := make([]byte, size-len(message))
	padding[0] = 0x80
	binary.BigEndian.PutUint64(padding[len(padding)-8:], uint64(len(message))*8)
	padded := make([]shaOctet, len(message), size)
	copy(padded, message)
	for _, value := range padding {
		padded = append(padded, octetBits(value))
	}

	var state [8]shaWord
	for i, iv := range shaIV {
		state[i] = wordBits(iv)
	}
	for i := 0; i < len(padded); i += blockSize {
		state = compressSHA256(api, state, padded[i:i+blockSize])
	}
	digest := make([]shaOctet, 32)
	for i, word := range state {
		for j := 0; j < 4; j++ {
			copy(digest[4*i+3-j][:], word[8*j:8*(j+1)])
		}
	}
	return digest
}

package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/keycommit"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const domain = "BSV/CCTP/continuity/v1\x00"

type G1 = sw_bls12381.G1Affine
type G2 = sw_bls12381.G2Affine
type GT = sw_bls12381.GTEl
type Fr = sw_bls12381.ScalarField
type Proof = keycommit.Proof

type Transcript struct {
	Asset   [32]byte
	SelfKey [32]byte
	Context [32]byte
	Count   uint8
	Prior   [2][32]byte
}

func (t Transcript) Digest() [32]byte {
	raw := append([]byte(domain), t.Asset[:]...)
	raw = append(raw, t.SelfKey[:]...)
	raw = append(raw, t.Context[:]...)
	raw = append(raw, t.Count)
	for _, digest := range t.Prior {
		raw = append(raw, digest[:]...)
	}
	first := sha256.Sum256(raw)
	return sha256.Sum256(first[:])
}

func limbs(data [32]byte) [2]*big.Int {
	return [2]*big.Int{new(big.Int).SetBytes(data[:16]), new(big.Int).SetBytes(data[16:])}
}

type padding struct {
	Key   keycommit.Key
	Proof Proof
	Limbs [2]*big.Int
}

// Circuit checks cryptographic continuity. BSV authenticates the transaction
// context and actual predecessor outpoints, and enforces the mint base case
// when there are no predecessors.
type Circuit struct {
	Digest  [2]frontend.Variable `gnark:",public"`
	Asset   [32]frontend.Variable
	SelfID  [32]frontend.Variable
	Context [32]frontend.Variable
	Count   frontend.Variable
	Prior   [2][32]frontend.Variable
	Key     keycommit.Key
	Proofs  [2]Proof

	pad padding `gnark:"-"`
}

func circuitTemplate(pad padding) *Circuit {
	c := &Circuit{Key: keycommit.Placeholder(), pad: pad}
	for i := range c.Proofs {
		c.Proofs[i].Commitments = make([]pedersen.Commitment[G1], 1)
	}
	return c
}

func uint128Pair(api frontend.API, data []uints.U8) [2]frontend.Variable {
	var result [2]frontend.Variable
	for i := range result {
		v := frontend.Variable(0)
		for _, b := range data[16*i : 16*(i+1)] {
			v = api.Add(api.Mul(v, 256), b.Val)
		}
		result[i] = v
	}
	return result
}

func hash256(api frontend.API, raw []uints.U8) ([]uints.U8, error) {
	first, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	first.Write(raw)
	second, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	second.Write(first.Sum())
	return second.Sum(), nil
}

func (c *Circuit) Define(api frontend.API) error {
	byteAPI, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	asset, keyID, context := make([]uints.U8, 32), make([]uints.U8, 32), make([]uints.U8, 32)
	for i := range asset {
		asset[i], keyID[i], context[i] = byteAPI.ValueOf(c.Asset[i]), byteAPI.ValueOf(c.SelfID[i]), byteAPI.ValueOf(c.Context[i])
	}
	if err := keycommit.Assert(api, &c.Key, uint128Pair(api, keyID)); err != nil {
		return fmt.Errorf("authenticate self key: %w", err)
	}
	zero, one, two := api.IsZero(c.Count), api.IsZero(api.Sub(c.Count, 1)), api.IsZero(api.Sub(c.Count, 2))
	api.AssertIsEqual(api.Add(zero, one, two), 1)
	active := [2]frontend.Variable{api.Add(one, two), two}
	message := uints.NewU8Array([]byte(domain))
	message = append(message, asset...)
	message = append(message, keyID...)
	message = append(message, context...)
	message = append(message, byteAPI.ValueOf(c.Count))

	priorBytes, err := assertPredecessorProofs(api, byteAPI, &c.Key, c.pad, active[:], c.Prior[:], c.Proofs[:])
	if err != nil {
		return err
	}
	message = append(message, priorBytes...)
	digest, err := hash256(api, message)
	if err != nil {
		return err
	}
	for i, value := range uint128Pair(api, digest) {
		api.AssertIsEqual(c.Digest[i], value)
	}
	return nil
}

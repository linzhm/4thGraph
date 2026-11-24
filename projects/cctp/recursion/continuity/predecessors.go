package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/keycommit"
)

func validPredecessorSlots(slots int) bool {
	return slots == 1 || slots == 2 || slots == 4
}

// predecessorActivity bounds count to [0, slots] and activates the first
// count entries. The caller ties count to the actual operation and inputs.
func predecessorActivity(api frontend.API, count frontend.Variable, slots int) ([]frontend.Variable, error) {
	if !validPredecessorSlots(slots) {
		return nil, fmt.Errorf("expected one, two, or four predecessor slots")
	}
	counts := make([]frontend.Variable, slots+1)
	counts[0] = api.IsZero(count)
	for i := 1; i <= slots; i++ {
		counts[i] = api.IsZero(api.Sub(count, i))
	}
	api.AssertIsEqual(api.Add(counts[0], counts[1], counts[2:]...), 1)
	active := make([]frontend.Variable, slots)
	active[slots-1] = counts[slots]
	for i := slots - 2; i >= 0; i-- {
		active[i] = api.Add(counts[i+1], active[i+1])
	}
	return active, nil
}

// assertPredecessorProofs checks every active slot against the same witnessed
// key and its ordered digest. Inactive slots require a zero digest and use
// the fixed padding key, proof, and limbs. The caller authenticates key with
// keycommit.Assert and derives active from the actual statement semantics.
// The result contains all digest bytes in slot order for the public statement.
func assertPredecessorProofs(api frontend.API, byteAPI *uints.Bytes, key *keycommit.Key, pad padding,
	active []frontend.Variable, priors [][32]frontend.Variable, proofs []Proof) ([]uints.U8, error) {
	if !validPredecessorSlots(len(priors)) || len(priors) != len(proofs) || len(priors) != len(active) {
		return nil, fmt.Errorf("expected equal activity, digest, and proof vectors of one, two, or four slots")
	}
	if len(pad.Proof.Commitments) != 1 {
		return nil, fmt.Errorf("expected one BSB22 padding proof commitment")
	}
	for i, proof := range proofs {
		if len(proof.Commitments) != 1 {
			return nil, fmt.Errorf("expected one BSB22 commitment for predecessor %d", i)
		}
	}
	verifier, err := recursive.NewVerifier[Fr, G1, G2, GT](api)
	if err != nil {
		return nil, err
	}
	curve, err := algebra.GetCurve[Fr, G1](api)
	if err != nil {
		return nil, err
	}
	pairing, err := algebra.GetPairing[G1, G2, GT](api)
	if err != nil {
		return nil, err
	}
	scalar, err := emulated.NewField[Fr](api)
	if err != nil {
		return nil, err
	}
	priorBytes := make([]uints.U8, 0, 32*len(priors))
	for i := range priors {
		prior := make([]uints.U8, 32)
		for j, value := range priors[i] {
			api.AssertIsEqual(api.Mul(api.Sub(1, active[i]), value), 0)
			prior[j] = byteAPI.ValueOf(value)
		}
		priorBytes = append(priorBytes, prior...)
		inputs := uint128Pair(api, prior)
		witness := recursive.Witness[Fr]{Public: make([]emulated.Element[Fr], 2)}
		for j, value := range inputs {
			selected := api.Select(active[i], value, pad.Limbs[j])
			witness.Public[j] = *scalar.FromBits(api.ToBinary(selected, 128)...)
		}
		selectedKey, err := verifier.SwitchVerificationKey(active[i], []keycommit.Key{pad.Key, *key})
		if err != nil {
			return nil, fmt.Errorf("select predecessor %d key: %w", i, err)
		}
		given, filler := &proofs[i], &pad.Proof
		proof := Proof{
			Ar:  *curve.Mux(active[i], &filler.Ar, &given.Ar),
			Bs:  *pairing.MuxG2(active[i], &filler.Bs, &given.Bs),
			Krs: *curve.Mux(active[i], &filler.Krs, &given.Krs),
			Commitments: []pedersen.Commitment[G1]{{
				G1El: *curve.Mux(active[i], &filler.Commitments[0].G1El, &given.Commitments[0].G1El),
			}},
			CommitmentPok: pedersen.KnowledgeProof[G1]{
				G1El: *curve.Mux(active[i], &filler.CommitmentPok.G1El, &given.CommitmentPok.G1El),
			},
		}
		if err := verifier.AssertProof(selectedKey, proof, witness,
			recursive.WithSubgroupCheck(), recursive.WithCompleteArithmetic()); err != nil {
			return nil, fmt.Errorf("verify predecessor %d: %w", i, err)
		}
	}
	return priorBytes, nil
}

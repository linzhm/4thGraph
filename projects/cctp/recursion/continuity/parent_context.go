package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/parentcheckpoint"
)

const parentReceiptTag = "BSV/CCTP/continuity-parents/v1\x00"
const parentReceiptPayloadSize = 1 + 2*32

type chronicleParentProfile struct {
	VerifierVin            int
	ScriptCode             []byte
	MinParents, MaxParents int
}

// chronicleParentMaterial derives an OTDA preimage and the actual final receipt
// from one case. Framing and verifier checks apply only to the selected case.
func chronicleParentMaterial(api frontend.API, branch parentcheckpoint.BoundParentCase,
	profile chronicleParentProfile, approvedVerifier [36]frontend.Variable,
) (preimage, payload []frontend.Variable, err error) {
	active, tx := branch.Selector, branch.Context
	if len(tx.Inputs) == 0 || len(tx.Inputs) >= 253 || len(tx.TxOuts) == 0 || len(tx.TxOuts) >= 253 ||
		profile.VerifierVin < 0 || profile.VerifierVin >= len(tx.Inputs) ||
		len(profile.ScriptCode) == 0 || len(profile.ScriptCode) >= 253 ||
		profile.MinParents < 0 || profile.MaxParents > 2 || profile.MinParents > profile.MaxParents {
		return nil, nil, fmt.Errorf("invalid bounded Chronicle predecessor profile")
	}
	if len(tx.Version) != 4 || len(tx.Locktime) != 4 {
		return nil, nil, fmt.Errorf("invalid authenticated predecessor header")
	}
	api.AssertIsBoolean(active)
	equalIfActive := func(a, b frontend.Variable) {
		api.AssertIsEqual(api.Mul(active, api.Sub(a, b)), 0)
	}

	// OTDA ALL keeps ordered outpoints and sequences, empties each other
	// script field, and binds the canonical full output vector.
	preimage = append([]frontend.Variable{}, tx.Version...)
	preimage = append(preimage, len(tx.Inputs))
	for i, input := range tx.Inputs {
		if len(input.Outpoint) != 36 || len(input.Sequence) != 4 {
			return nil, nil, fmt.Errorf("invalid authenticated predecessor vin %d", i)
		}
		preimage = append(preimage, input.Outpoint...)
		if i == profile.VerifierVin {
			for j, value := range approvedVerifier {
				equalIfActive(input.Outpoint[j], value)
			}
			for j, value := range []byte{0x61, 0, 0, 0x80} {
				equalIfActive(input.Sequence[j], value)
			}
			preimage = append(preimage, len(profile.ScriptCode))
			for _, value := range profile.ScriptCode {
				preimage = append(preimage, value)
			}
		} else {
			preimage = append(preimage, 0)
		}
		preimage = append(preimage, input.Sequence...)
	}
	preimage = append(preimage, len(tx.TxOuts))
	preimage = append(preimage, tx.Outputs...)
	preimage = append(preimage, tx.Locktime...)
	preimage = append(preimage, 0x61, 0, 0, 0)

	// Parse the actual final TxOut. A receipt-shaped suffix inside any other
	// locking script has no authority.
	receiptScriptSize := 2 + 1 + len(parentReceiptTag) + 1 + parentReceiptPayloadSize
	prefix := append(make([]byte, 8), byte(receiptScriptSize), 0x00, 0x6a, byte(len(parentReceiptTag)))
	prefix = append(prefix, []byte(parentReceiptTag)...)
	prefix = append(prefix, parentReceiptPayloadSize)
	receipt := tx.TxOuts[len(tx.TxOuts)-1]
	if len(receipt) != len(prefix)+parentReceiptPayloadSize {
		return nil, nil, fmt.Errorf("expected a canonical final receipt TxOut width")
	}
	for i, value := range prefix {
		equalIfActive(receipt[i], value)
	}
	payload = receipt[len(prefix):]
	count := payload[0]
	matches := [3]frontend.Variable{
		api.IsZero(count), api.IsZero(api.Sub(count, 1)), api.IsZero(api.Sub(count, 2)),
	}
	var allowed frontend.Variable = 0
	for _, match := range matches[profile.MinParents : profile.MaxParents+1] {
		allowed = api.Add(allowed, match)
	}
	equalIfActive(allowed, 1)
	for i, value := range payload[1:] {
		padding := matches[0]
		if i >= 32 {
			padding = api.Add(padding, matches[1])
		}
		equalIfActive(api.Mul(padding, value), 0)
	}

	return preimage, payload, nil
}

// chronicleParentDigest opens the predecessor statement from the selected
// authenticated layout. The caller supplies the current asset and self key,
// and verifier outpoints already approved by that same asset policy. The
// caller also checks the selected parent's output role.
func chronicleParentDigest(api frontend.API, branches []parentcheckpoint.BoundParentCase,
	profiles []chronicleParentProfile, asset, selfKey [32]frontend.Variable, approvedVerifiers [][36]frontend.Variable,
) ([32]frontend.Variable, error) {
	var digest [32]frontend.Variable
	if len(branches) == 0 || len(branches) != len(profiles) || len(branches) != len(approvedVerifiers) {
		return digest, fmt.Errorf("expected Chronicle profile and verifier authorization for each parent layout")
	}
	preimages := make([][]frontend.Variable, len(branches))
	lengths := make([]int, len(branches))
	selectors := make([]frontend.Variable, len(branches))
	payload := make([]frontend.Variable, parentReceiptPayloadSize)
	for i := range payload {
		payload[i] = 0
	}
	var width int
	for i, branch := range branches {
		raw, receipt, err := chronicleParentMaterial(api, branch, profiles[i], approvedVerifiers[i])
		if err != nil {
			return digest, err
		}
		preimages[i], lengths[i], selectors[i] = raw, len(raw), branch.Selector
		width = max(width, len(raw))
		for j, value := range receipt {
			payload[j] = api.Add(payload[j], api.Mul(branch.Selector, value))
		}
	}
	preimage := make([]frontend.Variable, width)
	for i := range preimage {
		preimage[i] = 0
	}
	for i, raw := range preimages {
		for j, value := range raw {
			preimage[j] = api.Add(preimage[j], api.Mul(selectors[i], value))
		}
	}
	context, err := freeze.SHA256dAtSelectedLength(api, preimage, lengths, selectors)
	if err != nil {
		return digest, err
	}
	message := make([]frontend.Variable, 0, len(domain)+3*32+parentReceiptPayloadSize)
	for _, value := range []byte(domain) {
		message = append(message, value)
	}
	message = append(message, asset[:]...)
	message = append(message, selfKey[:]...)
	message = append(message, context...)
	message = append(message, payload...)
	copy(digest[:], freeze.SHA256dBytes(api, message))
	return digest, nil
}

package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/conservation"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/parentcheckpoint"
)

const committedContinuityDomain = "BSV/CCTP/continuity/v2\x00"
const predecessorCommitmentDomain = "BSV/CCTP/predecessors/v2\x00"
const committedReceiptTag = "BSV/CCTP/continuity-parents/v2\x00"
const committedParentSlots = 4
const committedReceiptPayloadSize = 33
const tokenMetadataSize = freeze.FrozenOffset + 1 - 8

type wireTransferProfile struct {
	VerifierScriptCode []byte
	TokenPrefix        []byte
	TokenSuffix        []byte
}

func appendLiteral(message []frontend.Variable, data []byte) []frontend.Variable {
	for _, value := range data {
		message = append(message, value)
	}
	return message
}

func committedReceiptPrefix() []byte {
	size := 2 + 1 + len(committedReceiptTag) + 1 + committedReceiptPayloadSize
	prefix := append(make([]byte, 8), byte(size), 0, 0x6a, byte(len(committedReceiptTag)))
	return append(append(prefix, []byte(committedReceiptTag)...), committedReceiptPayloadSize)
}

func committedReceiptFromWire(api frontend.API, receipt []frontend.Variable) ([]frontend.Variable, error) {
	prefix := committedReceiptPrefix()
	if len(receipt) != len(prefix)+committedReceiptPayloadSize {
		return nil, fmt.Errorf("expected the final fixed-width predecessor receipt")
	}
	for i, value := range prefix {
		api.AssertIsEqual(receipt[i], value)
	}
	payload := receipt[len(prefix):]
	if _, err := predecessorActivity(api, payload[0], committedParentSlots); err != nil {
		return nil, err
	}
	empty := api.IsZero(payload[0])
	for i, value := range commitPredecessors(api, nil) {
		api.AssertIsEqual(api.Mul(empty, api.Sub(payload[1+i], value)), 0)
	}
	return payload, nil
}

func commitPredecessors(api frontend.API, ordered [][32]frontend.Variable) []frontend.Variable {
	message := appendLiteral(nil, []byte(predecessorCommitmentDomain))
	message = append(message, len(ordered))
	for i := range ordered {
		message = append(message, ordered[i][:]...)
	}
	for i := len(ordered); i < committedParentSlots; i++ {
		message = appendLiteral(message, make([]byte, 32))
	}
	return freeze.SHA256dBytes(api, message)
}

func committedContinuityDigest(api frontend.API, preimage, payload []frontend.Variable,
	asset, selfKey [32]frontend.Variable,
) [32]frontend.Variable {
	message := appendLiteral(nil, []byte(committedContinuityDomain))
	message = append(message, asset[:]...)
	message = append(message, selfKey[:]...)
	message = append(message, freeze.SHA256dBytes(api, preimage)...)
	message = append(message, payload...)
	var digest [32]frontend.Variable
	copy(digest[:], freeze.SHA256dBytes(api, message))
	return digest
}

// committedParentDigest reconstructs the selected predecessor's public
// statement without disclosing any of its own predecessor proof digests.
func committedParentDigest(api frontend.API, tx parentcheckpoint.BoundParentContext, verifierVin int,
	scriptCode []byte, asset, selfKey [32]frontend.Variable, approvedVerifier [36]frontend.Variable,
) ([32]frontend.Variable, error) {
	preimage, err := chronicleContextPreimage(api, 1, tx, verifierVin, scriptCode, approvedVerifier)
	if err != nil {
		return [32]frontend.Variable{}, err
	}
	payload, err := committedReceiptFromWire(api, tx.TxOuts[len(tx.TxOuts)-1])
	if err != nil {
		return [32]frontend.Variable{}, err
	}
	return committedContinuityDigest(api, preimage, payload, asset, selfKey), nil
}

func tokenStateFromWire(api frontend.API, output []frontend.Variable, profile wireTransferProfile,
	asset [32]frontend.Variable,
) ([]frontend.Variable, error) {
	lockLen := len(profile.TokenPrefix) + tokenMetadataSize + len(profile.TokenSuffix)
	if len(profile.TokenPrefix) == 0 || len(profile.TokenSuffix) == 0 || lockLen > 65535 {
		return nil, fmt.Errorf("invalid fixed token lock template")
	}
	compactSize := []byte{byte(lockLen)}
	if lockLen >= 253 {
		compactSize = []byte{0xfd, byte(lockLen), byte(lockLen >> 8)}
	}
	prefix := append(append([]byte{}, compactSize...), profile.TokenPrefix...)
	if len(output) != 8+len(prefix)+tokenMetadataSize+len(profile.TokenSuffix) {
		return nil, fmt.Errorf("unexpected token TxOut wire width")
	}
	for i, value := range prefix {
		api.AssertIsEqual(output[8+i], value)
	}
	metadata := output[8+len(prefix) : 8+len(prefix)+tokenMetadataSize]
	for i, value := range asset {
		api.AssertIsEqual(metadata[i], value)
	}
	for i, value := range profile.TokenSuffix {
		api.AssertIsEqual(output[8+len(prefix)+tokenMetadataSize+i], value)
	}
	// Prefix, suffix and length were checked above. Their normalized hash is
	// constant for this verifier-independent token template.
	normalized := append(append([]byte{}, prefix...), make([]byte, tokenMetadataSize)...)
	policy := sha256.Sum256(append(normalized, profile.TokenSuffix...))
	state := append(append([]frontend.Variable{}, output[:8]...), metadata...)
	return appendLiteral(state, policy[:]), nil
}

// wireTransferDigest checks the selected token TxOuts, ordered successors and
// committed predecessor statement. Bind each prior TxOut and its digest to
// the actual token vin with parent opening and recursive verification before
// using this result. BSV must pin the two public limbs to the authentic
// executing transaction and check each owner's signature.
func wireTransferDigest(api frontend.API, tx parentcheckpoint.BoundParentContext, priors [][]frontend.Variable,
	digests [][32]frontend.Variable, profile wireTransferProfile, asset, selfKey [32]frontend.Variable,
	verifier [36]frontend.Variable,
) ([32]frontend.Variable, error) {
	var digest [32]frontend.Variable
	if len(priors) < 1 || len(priors) > committedParentSlots || len(digests) != len(priors) ||
		len(tx.Inputs) != len(priors)+1 || len(tx.TxOuts) < 2 || len(tx.TxOuts) > 5 {
		return digest, fmt.Errorf("invalid bounded transfer shape")
	}
	preimage, err := chronicleContextPreimage(api, 1, tx, 0, profile.VerifierScriptCode, verifier)
	if err != nil {
		return digest, err
	}
	outpoints := make([][36]frontend.Variable, len(tx.Inputs))
	for i, input := range tx.Inputs {
		copy(outpoints[i][:], input.Outpoint)
	}
	conservation.AssertDistinctOutpoints(api, outpoints)

	var states []frontend.Variable
	for _, outputs := range [][][]frontend.Variable{priors, tx.TxOuts[:len(tx.TxOuts)-1]} {
		for _, output := range outputs {
			state, err := tokenStateFromWire(api, output, profile, asset)
			if err != nil {
				return digest, err
			}
			states = append(states, state...)
		}
	}
	if err := conservation.AssertTransfer(api, states, len(priors)); err != nil {
		return digest, err
	}

	payload, err := committedReceiptFromWire(api, tx.TxOuts[len(tx.TxOuts)-1])
	if err != nil {
		return digest, err
	}
	api.AssertIsEqual(payload[0], len(priors))
	for i, value := range commitPredecessors(api, digests) {
		api.AssertIsEqual(payload[1+i], value)
	}
	return committedContinuityDigest(api, preimage, payload, asset, selfKey), nil
}

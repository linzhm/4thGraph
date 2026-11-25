package parentcheckpoint

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/freeze"
)

const BacktraceDomain = "BSV/CCTP/parent-openings/v1\x00"
const BacktraceProvenanceDomain = "BSV/CCTP/parent-openings-and-provenance/v1\x00"
const BacktraceStatementSize = len(BacktraceDomain) + 32 + 72 + 2*78
const BacktraceProvenanceStatementSize = len(BacktraceProvenanceDomain) + 32 + 32 + 72 + 2*78
const BacktraceParentBytes = 4075
const BacktraceMintBytes = 903

const (
	backtraceQuantityAt = 30
	backtraceOwnerAt    = 56
	backtraceFundingAt  = 147
	backtraceTokenBytes = 769
)

//go:embed backtrace-token-template.hex
var backtraceTemplateHex string

var backtraceLayouts = []ParentOutputLayout{
	{FixedParentLayout{[]int{72}, []int{backtraceTokenBytes}}, []int{0}},
	{FixedParentLayout{[]int{1624, 376, 376}, []int{backtraceTokenBytes, backtraceTokenBytes}}, []int{0, 1}},
}

type BacktraceStatement [BacktraceStatementSize]byte
type BacktraceProvenanceStatement [BacktraceProvenanceStatementSize]byte

func (s BacktraceStatement) Encode() []byte { return s[:] }

func (s BacktraceStatement) Digest() [32]byte {
	hash := sha256.Sum256(s[:])
	return sha256.Sum256(hash[:])
}

func (s BacktraceStatement) Limbs() [2]*big.Int {
	digest := s.Digest()
	return [2]*big.Int{new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:])}
}

func (s BacktraceProvenanceStatement) Encode() []byte { return s[:] }

func (s BacktraceProvenanceStatement) Digest() [32]byte {
	hash := sha256.Sum256(s[:])
	return sha256.Sum256(hash[:])
}

func (s BacktraceProvenanceStatement) Limbs() [2]*big.Int {
	digest := s.Digest()
	return [2]*big.Int{new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:])}
}

func BacktraceProvenanceAssignment(wire, raw []byte) (BacktraceProvenanceStatement, *BacktraceProvenance, error) {
	var statement BacktraceProvenanceStatement
	if len(wire) != len(statement) || !bytes.HasPrefix(wire, []byte(BacktraceProvenanceDomain)) {
		return statement, nil, fmt.Errorf("invalid backtrace provenance statement encoding")
	}
	copy(statement[:], wire)
	root := wire[len(BacktraceProvenanceDomain):][:32]
	baseWire := append([]byte(BacktraceDomain), wire[len(BacktraceProvenanceDomain)+32:]...)
	_, opening, err := BacktraceAssignment(baseWire, raw)
	if err != nil {
		return statement, nil, err
	}
	limbs := statement.Limbs()
	opening.Public = [2]frontend.Variable{limbs[0], limbs[1]}
	circuit := &BacktraceProvenance{Openings: *opening}
	for i, value := range root {
		circuit.Root[i] = value
	}
	return statement, circuit, nil
}

type BacktraceOpenings struct {
	Public    [2]frontend.Variable `gnark:",public"`
	FundingID [32]frontend.Variable
	Outpoints [2][36]frontend.Variable
	Layout    [2]frontend.Variable
	Parent    [2][BacktraceParentBytes]frontend.Variable
}

func (c *BacktraceOpenings) Define(api frontend.API) error {
	payload, err := c.open(api)
	if err != nil {
		return err
	}
	freeze.AssertSHA256dStatement(api, BacktraceDomain, payload, c.Public)
	return nil
}

func (c *BacktraceOpenings) open(api frontend.API) ([]frontend.Variable, error) {
	template, err := hex.DecodeString(strings.TrimSpace(backtraceTemplateHex))
	if err != nil || len(template) != backtraceTokenBytes {
		return nil, fmt.Errorf("invalid covenant token template")
	}
	payload := make([]frontend.Variable, 0, BacktraceStatementSize-len(BacktraceDomain))
	payload = append(payload, c.FundingID[:]...)
	for _, point := range c.Outpoints {
		payload = append(payload, point[:]...)
	}
	for i := range c.Parent {
		selected, err := BindParentOutput(api, c.Parent[i][:], c.Outpoints[i][:], c.Layout[i], backtraceLayouts)
		if err != nil {
			return nil, err
		}
		api.AssertIsEqual(selected.Satoshis, 1000)
		var source [36]frontend.Variable
		for j := range source {
			source[j] = 0
			for _, layout := range selected.Layouts {
				source[j] = api.Add(source[j], api.Mul(layout.Selector, layout.Context.Inputs[0].Outpoint[j]))
			}
		}
		for j, constant := range template {
			switch {
			case j >= backtraceQuantityAt && j < backtraceQuantityAt+8:
			case j >= backtraceOwnerAt && j < backtraceOwnerAt+33:
			case j >= backtraceFundingAt && j < backtraceFundingAt+32:
				api.AssertIsEqual(selected.Script[j], c.FundingID[j-backtraceFundingAt])
			default:
				api.AssertIsEqual(selected.Script[j], constant)
			}
		}
		payload = append(payload, c.Layout[i])
		payload = append(payload, source[:]...)
		payload = append(payload, selected.Script[backtraceQuantityAt:backtraceQuantityAt+8]...)
		payload = append(payload, selected.Script[backtraceOwnerAt:backtraceOwnerAt+33]...)
	}
	return payload, nil
}

// BacktraceProvenance additionally authenticates each source against the
// issuance root and the current proof-verifier funding. Its caller must bind
// both identifiers and the actual outpoints to Script and enforce conservation.
type BacktraceProvenance struct {
	Openings BacktraceOpenings
	Root     [32]frontend.Variable
}

func (c *BacktraceProvenance) Define(api frontend.API) error {
	payload, err := c.Openings.open(api)
	if err != nil {
		return err
	}
	for i, layout := range c.Openings.Layout {
		claim := payload[32+72+i*78:][:78]
		source, amount := claim[1:37], parentUint64(api, claim[37:45])
		for j := range source[:32] {
			want := api.Select(layout, c.Openings.FundingID[j], c.Root[j])
			api.AssertIsEqual(source[j], want)
		}
		index := parentUint64(api, source[32:])
		isFirst := api.IsZero(index)
		isSecond := api.IsZero(api.Sub(index, 1))
		isThirdMint := api.Mul(api.Sub(1, layout), api.IsZero(api.Sub(index, 2)))
		api.AssertIsEqual(api.Add(isFirst, isSecond, isThirdMint), 1)
		issued := api.Add(api.Mul(isFirst, 300), api.Mul(isSecond, 200), api.Mul(isThirdMint, 150))
		api.AssertIsEqual(api.Mul(api.Sub(1, layout), api.Sub(issued, amount)), 0)
	}
	freeze.AssertSHA256dStatement(api, BacktraceProvenanceDomain, append(c.Root[:], payload...), c.Openings.Public)
	return nil
}

// BacktraceAssignment receives two length-tagged complete raw parents.
func BacktraceAssignment(wire, raw []byte) (BacktraceStatement, *BacktraceOpenings, error) {
	var statement BacktraceStatement
	if len(wire) != len(statement) || !bytes.HasPrefix(wire, []byte(BacktraceDomain)) {
		return statement, nil, fmt.Errorf("invalid backtrace statement encoding")
	}
	copy(statement[:], wire)
	limbs := statement.Limbs()
	c := &BacktraceOpenings{Public: [2]frontend.Variable{limbs[0], limbs[1]}}
	for i := range c.FundingID {
		c.FundingID[i] = wire[len(BacktraceDomain)+i]
	}
	for i := range c.Parent {
		for j := range c.Outpoints[i] {
			c.Outpoints[i][j] = wire[len(BacktraceDomain)+32+i*36+j]
		}
		if len(raw) == 0 || raw[0] > 1 {
			return statement, nil, fmt.Errorf("invalid parent layout")
		}
		c.Layout[i] = raw[0]
		length := BacktraceMintBytes
		if raw[0] == 1 {
			length = BacktraceParentBytes
		}
		raw = raw[1:]
		if len(raw) < length {
			return statement, nil, fmt.Errorf("truncated parent %d", i)
		}
		for j := range c.Parent[i] {
			c.Parent[i][j] = 0
		}
		for j, value := range raw[:length] {
			c.Parent[i][j] = value
		}
		raw = raw[length:]
	}
	if len(raw) != 0 {
		return statement, nil, fmt.Errorf("excess parent encoding")
	}
	return statement, c, nil
}

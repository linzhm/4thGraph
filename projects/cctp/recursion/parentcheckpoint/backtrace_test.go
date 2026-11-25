package parentcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func backtraceTestParent(t *testing.T, layout int, source []byte, units ...uint64) ([]byte, [][]byte) {
	t.Helper()
	shape := backtraceLayouts[layout].Layout
	if len(units) != len(shape.OutputScriptLengths) || len(source) != 36 {
		t.Fatal("test layout differs")
	}
	template, err := hex.DecodeString(strings.TrimSpace(backtraceTemplateHex))
	if err != nil {
		t.Fatal(err)
	}
	wire := []byte{1, 0, 0, 0, byte(len(shape.InputScriptLengths))}
	for i, length := range shape.InputScriptLengths {
		point := source
		if i > 0 {
			point = bytes.Repeat([]byte{byte(i)}, 36)
		}
		wire = append(wire, point...)
		wire = append(wire, parentCompactSize(uint64(length))...)
		wire = append(wire, make([]byte, length)...)
		wire = binary.LittleEndian.AppendUint32(wire, ^uint32(0))
	}
	wire = append(wire, byte(len(units)))
	claims := make([][]byte, len(units))
	for i, quantity := range units {
		script := append([]byte(nil), template...)
		binary.LittleEndian.PutUint64(script[backtraceQuantityAt:], quantity)
		script[backtraceOwnerAt] = 2
		copy(script[backtraceFundingAt:], bytes.Repeat([]byte{0x46}, 32))
		wire = binary.LittleEndian.AppendUint64(wire, 1000)
		wire = append(wire, parentCompactSize(uint64(len(script)))...)
		wire = append(wire, script...)
		claims[i] = append(append([]byte{byte(layout)}, source...), script[backtraceQuantityAt:backtraceQuantityAt+8]...)
		claims[i] = append(claims[i], script[backtraceOwnerAt:backtraceOwnerAt+33]...)
	}
	return append(wire, 0, 0, 0, 0), claims
}

func TestBacktraceProvenanceSeparatesOpeningAndSourceAuthorization(t *testing.T) {
	root := bytes.Repeat([]byte{0x52}, 32)
	funding := bytes.Repeat([]byte{0x46}, 32)
	first, firstClaims := backtraceTestParent(t, 1, binary.LittleEndian.AppendUint32(funding, 0), 275, 225)
	second, secondClaims := backtraceTestParent(t, 0, binary.LittleEndian.AppendUint32(root, 2), 150)
	double := func(b []byte) [32]byte {
		inner := sha256.Sum256(b)
		return sha256.Sum256(inner[:])
	}
	wire := append([]byte(BacktraceDomain), funding...)
	for i, parent := range [][]byte{first, second} {
		hash := double(parent)
		wire = append(wire, hash[:]...)
		wire = binary.LittleEndian.AppendUint32(wire, uint32(1-i))
	}
	wire = append(wire, firstClaims[1]...)
	wire = append(wire, secondClaims[0]...)
	raw := append(append([]byte{1}, first...), 0)
	raw = append(raw, second...)
	_, opening, err := BacktraceAssignment(wire, raw)
	if err != nil {
		t.Fatal(err)
	}
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &BacktraceProvenance{})
	if err != nil {
		t.Fatal(err)
	}

	for _, valid := range []bool{true, false} {
		issuer := append([]byte(nil), root...)
		if !valid {
			issuer[0] ^= 1
		}
		statement := append([]byte(BacktraceProvenanceDomain), issuer...)
		statement = append(statement, wire[len(BacktraceDomain):]...)
		digest := double(statement)
		candidate := BacktraceProvenance{Openings: *opening}
		candidate.Openings.Public = [2]frontend.Variable{
			new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:]),
		}
		for i, value := range issuer {
			candidate.Root[i] = value
		}
		witness, err := frontend.NewWitness(&candidate, field)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ccs.Solve(witness)
		if (err == nil) != valid {
			t.Fatalf("issuer is correct=%v, solve returned %v", valid, err)
		}
	}
}

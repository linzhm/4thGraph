package parentcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func tokenWire() []byte {
	raw := []byte{2, 0, 0, 0, 2}
	raw = append(raw, bytes.Repeat([]byte{0x31}, 32)...)
	raw = binary.LittleEndian.AppendUint32(raw, 0)
	raw = append(raw, 0xfd, 0xf6, 0x06)
	raw = append(raw, bytes.Repeat([]byte{0x42}, 1782)...)
	raw = binary.LittleEndian.AppendUint32(raw, 0xffffffff)
	raw = append(raw, bytes.Repeat([]byte{0x53}, 32)...)
	raw = binary.LittleEndian.AppendUint32(raw, 2)
	raw = append(raw, 0)
	raw = binary.LittleEndian.AppendUint32(raw, 0xffffffff)
	raw = append(raw, 1)
	raw = binary.LittleEndian.AppendUint64(raw, 1000)
	raw = append(raw, 0xfd, 0x0a, 0x06)
	lock := []byte("\x12BSV/CCTP/token/v2\x00\x4a")
	lock = append(lock, bytes.Repeat([]byte{0x64}, 32)...)
	lock = binary.LittleEndian.AppendUint64(lock, 640)
	lock = append(lock, 0x03)
	lock = append(lock, bytes.Repeat([]byte{0x75}, 32)...)
	lock = append(lock, 0)
	lock = append(lock, bytes.Repeat([]byte{0x86}, 1546-len(lock))...)
	raw = append(raw, lock...)
	return binary.LittleEndian.AppendUint32(raw, 3)
}

func tokenStatement(t *testing.T, raw []byte) Statement {
	t.Helper()
	const processed = 1856
	hash := sha256.New()
	if _, err := hash.Write(raw[:processed]); err != nil {
		t.Fatal(err)
	}
	state, err := hash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil || len(state) < 36 || string(state[:4]) != "sha\x03" {
		t.Fatal("unrecognized standard-library SHA-256 checkpoint format")
	}
	var statement Statement
	txid, suffix := hash256(raw), hash256(raw[processed:])
	copy(statement[:32], txid[:])
	copy(statement[32:64], state[4:36])
	binary.LittleEndian.PutUint64(statement[64:], processed)
	binary.LittleEndian.PutUint32(statement[72:], 1871)
	binary.LittleEndian.PutUint32(statement[76:], 1)
	copy(statement[80:112], suffix[:])
	return statement
}

func TestTokenCheckpoint(t *testing.T) {
	ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &TokenCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if ccs.GetNbPublicVariables() != 3 || ccs.GetNbSecretVariables() != 3433 ||
		len(ccs.GetCommitments().(constraint.Groth16Commitments)) != 0 {
		t.Fatal("expected a two-limb plain proof with one private raw parent")
	}
	t.Logf("%d constraints", ccs.GetNbConstraints())
	raw := tokenWire()
	valid := tokenStatement(t, raw)
	solve := func(t *testing.T, actual []byte, declared Statement, expectValid bool) {
		t.Helper()
		assignment, err := declared.TokenAssignment(actual)
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(assignment, fr.Modulus())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(witness); (err == nil) != expectValid {
			t.Fatalf("unexpected solver result, wanted valid=%t: %v", expectValid, err)
		}
	}
	t.Run("active-token-checkpoint", func(t *testing.T) { solve(t, raw, valid, true) })
	for _, claim := range []struct {
		name   string
		offset int
	}{
		{"wrong-checkpoint", 32}, {"wrong-offset", 72}, {"wrong-suffix", 80}, {"reserved-word", 112},
	} {
		t.Run(claim.name, func(t *testing.T) {
			mutant := valid
			mutant[claim.offset] ^= 1
			solve(t, raw, mutant, false)
		})
	}
	for _, field := range []struct {
		name   string
		offset int
	}{
		{"wrong-input-witness-size", 42}, {"nonempty-sponsor-witness", 1866},
		{"wrong-output-script-size", 1881}, {"wrong-token-marker", 1884}, {"frozen-token", 1976},
	} {
		t.Run(field.name, func(t *testing.T) {
			mutant := bytes.Clone(raw)
			mutant[field.offset] ^= 1
			solve(t, mutant, tokenStatement(t, mutant), false)
		})
	}
}

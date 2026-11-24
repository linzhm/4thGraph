package parentcheckpoint

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func referenceParent() [ParentSize]byte {
	var raw [ParentSize]byte
	binary.LittleEndian.PutUint32(raw[:], 2)
	raw[4] = 1
	for i := 5; i < 37; i++ {
		raw[i] = 0x89
	}
	binary.LittleEndian.PutUint32(raw[37:], 3)
	copy(raw[41:], []byte{0xfd, 0x03, 0x01, 0x4d, 0x00, 0x01})
	for i := 0; i < 256; i++ {
		raw[47+i] = byte(i)
	}
	binary.LittleEndian.PutUint32(raw[303:], 0x12345678)
	raw[307] = 2
	binary.LittleEndian.PutUint64(raw[308:], 1234)
	copy(raw[316:], []byte{1, 0x51})
	binary.LittleEndian.PutUint64(raw[318:], 5678)
	copy(raw[326:], []byte{1, 0x52})
	binary.LittleEndian.PutUint32(raw[328:], 17)
	return raw
}

func hash256(raw []byte) [32]byte {
	first := sha256.Sum256(raw)
	return sha256.Sum256(first[:])
}

// Derive independent host assertions from the standard library's SHA state
// serialization. Its versioned SHA-256 encoding places the eight big-endian
// chaining words immediately after the four-byte tag.
func referenceStatement(t *testing.T, raw []byte) Statement {
	t.Helper()
	h := sha256.New()
	if _, err := h.Write(raw[:ProcessedLength]); err != nil {
		t.Fatal(err)
	}
	internal, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil || len(internal) < 36 || string(internal[:4]) != "sha\x03" {
		t.Fatal("unrecognized standard-library SHA-256 checkpoint format")
	}
	var statement Statement
	txid, suffix, outputs := hash256(raw), hash256(raw[ProcessedLength:]), hash256(raw[OutputStart:OutputEnd])
	copy(statement[:32], txid[:])
	copy(statement[32:64], internal[4:36])
	binary.LittleEndian.PutUint64(statement[64:], ProcessedLength)
	binary.LittleEndian.PutUint32(statement[72:], OutputCountOffset)
	binary.LittleEndian.PutUint32(statement[76:], OutputCount)
	copy(statement[80:112], suffix[:])
	copy(statement[112:], outputs[:])
	return statement
}

func TestBoundedParentCheckpoint(t *testing.T) {
	started := time.Now()
	ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	if ccs.GetNbPublicVariables() != 3 || ccs.GetNbSecretVariables() != ParentSize ||
		len(ccs.GetCommitments().(constraint.Groth16Commitments)) != 0 {
		t.Fatal("expected a two-limb plain proof and only the raw-parent witness")
	}
	t.Logf("%d constraints, %d private bytes, two public limbs, no commitment, compiled in %s",
		ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), time.Since(started))
	raw := referenceParent()
	valid := referenceStatement(t, raw[:])
	digest := valid.Digest()
	// Separately constructed with Python's parent_prefix and hashlib.
	if hex.EncodeToString(digest[:]) != "e19a3b84c55b3ce977bff8c99b2bea40683df7a6641800a13a565c8afe3c0a65" ||
		hex.EncodeToString(valid[32:64]) != "741fbb3478011ee0a9760130a8d57965de5b35ebdc55648d5c486b342daaf34e" {
		t.Fatal("reference disagrees with the Python parent checkpoint vector")
	}
	parsed, err := ParseStatement(valid.Encode())
	if err != nil || parsed != valid || EncodedSize != 174 {
		t.Fatal("invalid parent checkpoint wire round-trip")
	}
	solve := func(t *testing.T, statement Statement, actual []byte, expectValid bool) {
		t.Helper()
		assignment, err := statement.Assignment(actual)
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(assignment, fr.Modulus())
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if _, err := ccs.Solve(witness); (err == nil) != expectValid {
			t.Fatalf("unexpected solver result, wanted valid=%t: %v", expectValid, err)
		}
		if expectValid {
			t.Logf("solved valid statement in %s", time.Since(started))
		}
	}
	t.Run("actual-midstate-and-txid", func(t *testing.T) { solve(t, valid, raw[:], true) })
	for _, claim := range []struct {
		name   string
		offset int
	}{
		{"changed-claimed-txid", 0},
		{"changed-claimed-state", 32},
		{"changed-processed-length", 64},
		{"changed-output-count-offset", 72},
		{"changed-output-count", 76},
		{"changed-suffix-hash", 80},
		{"changed-output-vector-hash", 112},
	} {
		t.Run(claim.name, func(t *testing.T) {
			mutant := valid
			mutant[claim.offset] ^= 1
			solve(t, mutant, raw[:], false)
		})
	}
	for _, boundary := range []struct {
		name   string
		offset int
	}{
		{"wrong-input-count", 4},
		{"wrong-script-compact-size", 41},
		{"wrong-push-encoding", 44},
		{"wrong-output-count", 307},
		{"wrong-output-script-length", 316},
		{"nonmonetary-output", 315},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			mutant := raw
			mutant[boundary.offset] ^= 0x80
			// Even accurate hashes of the malformed wire must fail.
			solve(t, referenceStatement(t, mutant[:]), mutant[:], false)
		})
	}
	for _, index := range []int{100, 260} {
		mutant := raw
		mutant[index] ^= 1
		solve(t, valid, mutant[:], false)
	}
	if _, err := valid.Assignment(raw[:ParentSize-1]); err == nil {
		t.Fatal("accepted a truncated raw parent")
	}
}

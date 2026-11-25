package parentbinding

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

func projectionTransaction() []byte {
	raw := []byte{2, 0, 0, 0, 2}
	raw = append(raw, bytes.Repeat([]byte{0x32}, 32)...)
	raw = binary.LittleEndian.AppendUint32(raw, 3)
	raw = append(raw, 21, 20)
	raw = append(raw, bytes.Repeat([]byte{0x56}, 20)...)
	raw = binary.LittleEndian.AppendUint32(raw, 0x80000061)
	raw = append(raw, bytes.Repeat([]byte{0x78}, 32)...)
	raw = binary.LittleEndian.AppendUint32(raw, 5)
	raw = append(raw, 0)
	raw = binary.LittleEndian.AppendUint32(raw, 0xffffffff)
	raw = append(raw, 2)
	raw = binary.LittleEndian.AppendUint64(raw, 700)
	raw = append(raw, 1, 0x51)
	raw = binary.LittleEndian.AppendUint64(raw, 324)
	raw = append(raw, 1, 0x51)
	return binary.LittleEndian.AppendUint32(raw, 0)
}

func TestSHA256ProjectionLeaf(t *testing.T) {
	const width = 2
	spans := []SHA256FieldSpan{{0, 5}, {5, 36}, {63, 4}, {103, 6}, {109, 8}}
	projection, err := NewSHA256ProjectionLeaf(width, spans)
	if err != nil {
		t.Fatal(err)
	}
	spans[0].Offset = 1 // The circuit owns its configured layout.
	field := ecc.BLS12_381.ScalarField()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, projection)
	if err != nil {
		t.Fatal(err)
	}
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	if ccs.GetNbPublicVariables() != 10 || ccs.GetNbSecretVariables() != 128 ||
		len(commitments) != 1 || len(commitments[0].GetPublicCommitted()) != 0 {
		t.Fatal("expected five SHA scalars and four projection limbs with 128 private block bytes")
	}
	t.Logf("constraints=%d public=9 private=128 commitments=1", ccs.GetNbConstraints())
	raw := projectionTransaction()[:width*blockSize]
	iv := nativeSHA256State(t, nil)
	assign := func(t *testing.T, blocks []byte) *SHA256ProjectionLeaf {
		t.Helper()
		assignment, err := projection.Assignment(0, blocks, iv, nativeSHA256State(t, blocks))
		if err != nil {
			t.Fatal(err)
		}
		return assignment
	}
	makeWitness := func(t *testing.T, assignment *SHA256ProjectionLeaf) witness.Witness {
		t.Helper()
		w, err := frontend.NewWitness(assignment, field)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	honest := assign(t, raw)
	good := makeWitness(t, honest)
	if _, err := ccs.Solve(good); err != nil {
		t.Fatal(err)
	}
	public, err := good.Public()
	if err != nil {
		t.Fatal(err)
	}
	actual := public.Vector().(fr.Vector)
	expected := []byte{2, 0, 0, 0, 2}
	expected = append(expected, bytes.Repeat([]byte{0x32}, 32)...)
	expected = binary.LittleEndian.AppendUint32(expected, 3)
	expected = binary.LittleEndian.AppendUint32(expected, 0x80000061)
	expected = append(expected, 0, 0xff, 0xff, 0xff, 0xff, 2)
	expected = binary.LittleEndian.AppendUint64(expected, 700)
	if actual[4].BigInt(new(big.Int)).Sign() != 0 {
		t.Fatal("the public start block must precede the projection limbs")
	}
	for i, want := range [][]byte{expected[:16], expected[16:32], expected[32:48], expected[48:]} {
		if actual[5+i].BigInt(new(big.Int)).Cmp(new(big.Int).SetBytes(want)) != 0 {
			t.Fatalf("incorrect public projection limb %d", i)
		}
	}

	altered := bytes.Clone(raw)
	altered[109] ^= 1 // Change the claimed first output's satoshis.
	other := assign(t, altered)
	if _, err := ccs.Solve(makeWitness(t, other)); err != nil {
		t.Fatal(err)
	}
	mixed := *other
	mixed.Projection = honest.Projection
	if _, err := ccs.Solve(makeWitness(t, &mixed)); err == nil {
		t.Fatal("a valid hash transition accepted a projection from another transaction")
	}
	badLimb := *honest
	badLimb.Projection = slices.Clone(honest.Projection)
	badLimb.Projection[3] = new(big.Int).Add(honest.Projection[3].(*big.Int), new(big.Int).Lsh(big.NewInt(1), 88))
	if _, err := ccs.Solve(makeWitness(t, &badLimb)); err == nil {
		t.Fatal("accepted extra high bytes on the short last limb")
	}

	changedWitness := *honest
	changedWitness.Segment.Blocks = slices.Clone(honest.Segment.Blocks)
	changedWitness.Segment.Blocks[63] = uint16(raw[63]) + 256
	if _, err := ccs.Solve(makeWitness(t, &changedWitness)); err == nil {
		t.Fatal("accepted a non-byte value in a projected range")
	}

	privateOnly := bytes.Clone(raw)
	privateOnly[45] ^= 1
	another := assign(t, privateOnly)
	another.Projection = honest.Projection
	if _, err := ccs.Solve(makeWitness(t, another)); err != nil {
		t.Fatal("unprojected bytes should be authenticated only by the SHA transition", err)
	}
	if _, err := projection.Assignment(0, raw[:blockSize], iv, nativeSHA256State(t, raw)); err == nil {
		t.Fatal("accepted a different segment width")
	}
	if os.Getenv("CCTP_SHA256_PROJECTION_NATIVE_TEST") == "1" {
		t.Run("native-rejects-mismatched-field", func(t *testing.T) {
			wrong := *honest
			wrong.Projection = other.Projection
			checkNativeSHA256Projection(t, ccs, good, makeWitness(t, &wrong))
		})
	}
}

func TestInvalidSHA256ProjectionLayout(t *testing.T) {
	for _, spans := range [][]SHA256FieldSpan{
		nil, {{-1, 1}}, {{1, 0}}, {{63, 2}}, {{2, 8}, {5, 1}}, {{5, 1}, {2, 1}},
	} {
		if _, err := NewSHA256ProjectionLeaf(1, spans); err == nil {
			t.Fatalf("accepted invalid projection spans: %v", spans)
		}
	}
	if _, err := NewSHA256ProjectionLeaf(0, []SHA256FieldSpan{{0, 1}}); err == nil {
		t.Fatal("accepted an empty segment layout")
	}
}

func checkNativeSHA256Projection(t *testing.T, ccs constraint.ConstraintSystem, good, wrong witness.Witness) {
	t.Helper()
	field := ecc.BLS12_381.ScalarField()
	started := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("setup=%s", time.Since(started))
	started = time.Now()
	proof, err := groth16.Prove(ccs, pk, good, recursive.GetNativeProverOptions(field, field))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prove=%s", time.Since(started))
	public, err := good.Public()
	if err != nil {
		t.Fatal(err)
	}
	verify := recursive.GetNativeVerifierOptions(field, field)
	started = time.Now()
	if err := groth16.Verify(proof, vk, public, verify); err != nil {
		t.Fatal(err)
	}
	t.Logf("verify=%s", time.Since(started))
	wrongPublic, err := wrong.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, wrongPublic, verify); err == nil {
		t.Fatal("the original proof verified with a different field projection")
	}
}

// Command recursion checks two distinct CCTP split proofs inside a BLS12-381
// Groth16 circuit. The caller-supplied transaction commitment represents a
// candidate MIMO relation. It is not an authenticated Bitcoin transaction.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	blsGroth16 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
	blsConstraint "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	frontendcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

const (
	parentDomain = "BSV/CCTP/transfer/v1\x00"
	outerDomain  = "BSV/CCTP/recursion-spike/v1\x00"
	assetSize    = 32
	assetEnd     = len(parentDomain) + assetSize
	identitySize = assetEnd + 32
	bodySize     = 32 + 2 + 12 + 2 + 24
	mimoSize     = identitySize + bodySize + 12
)

type innerProof = recursive.Proof[sw_bls12381.G1Affine, sw_bls12381.G2Affine]
type innerKey = recursive.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]
type innerWitness = recursive.Witness[sw_bls12381.ScalarField]

type aggregate struct {
	Digest     [2]frontend.Variable `gnark:",public"`
	Context    []frontend.Variable  // Fixed-asset profile's candidate hash.
	Asset      []frontend.Variable  // Portable profile's common asset ID.
	ChildTail  []frontend.Variable  // Portable profile's child statement after asset ID.
	ParentBody [2][bodySize]frontend.Variable
	Proofs     [2]innerProof

	identity [identitySize]byte `gnark:"-"`
	key      innerKey           `gnark:"-"`
}

func hash256(api frontend.API, message []uints.U8) ([]uints.U8, error) {
	digest, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	digest.Write(message)
	first := digest.Sum()
	second, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	second.Write(first)
	return second.Sum(), nil
}

func (c *aggregate) Define(api frontend.API) error {
	bytes, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	scalar, err := emulated.NewField[sw_bls12381.ScalarField](api)
	if err != nil {
		return err
	}
	verifier, err := recursive.NewVerifier[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](api)
	if err != nil {
		return err
	}
	commitment := uints.NewU8Array([]byte(outerDomain))
	parentPrefix := uints.NewU8Array(c.identity[:])
	if len(c.Asset) == 0 {
		for _, value := range c.Context {
			commitment = append(commitment, bytes.ValueOf(value))
		}
	} else {
		child := uints.NewU8Array([]byte(parentDomain))
		for i, value := range c.Asset {
			b := bytes.ValueOf(value)
			child = append(child, b)
			parentPrefix[len(parentDomain)+i] = b
		}
		for _, value := range c.ChildTail {
			child = append(child, bytes.ValueOf(value))
		}
		context, err := hash256(api, child)
		if err != nil {
			return fmt.Errorf("child SHA256: %w", err)
		}
		commitment = append(commitment, context...)
	}
	var parentDigests [2][]uints.U8
	for i, body := range c.ParentBody {
		statement := append([]uints.U8(nil), parentPrefix...)
		for _, value := range body {
			statement = append(statement, bytes.ValueOf(value))
		}
		parentDigests[i], err = hash256(api, statement)
		if err != nil {
			return fmt.Errorf("parent %d SHA256: %w", i, err)
		}
		commitment = append(commitment, parentDigests[i]...)
		parent := innerWitness{Public: make([]emulated.Element[sw_bls12381.ScalarField], 2)}
		for j := range parent.Public {
			// The repository splits a 32-byte digest into big-endian uint128s.
			// emulated.FromBits takes little-endian bits, so walk bytes backward.
			bits := make([]frontend.Variable, 0, 128)
			for k := (j+1)*16 - 1; k >= j*16; k-- {
				bits = append(bits, api.ToBinary(parentDigests[i][k].Val, 8)...)
			}
			parent.Public[j] = *scalar.FromBits(bits...)
		}
		err = verifier.AssertProof(c.key, c.Proofs[i], parent,
			recursive.WithSubgroupCheck(), recursive.WithCompleteArithmetic())
		if err != nil {
			return fmt.Errorf("parent %d proof: %w", i, err)
		}
	}
	coincident := frontend.Variable(1)
	for i := range parentDigests[0] {
		equal := api.IsZero(api.Sub(parentDigests[0][i].Val, parentDigests[1][i].Val))
		coincident = api.Mul(coincident, equal)
	}
	api.AssertIsEqual(coincident, 0)
	outer, err := hash256(api, commitment)
	if err != nil {
		return err
	}
	for i, expected := range c.Digest {
		limb := frontend.Variable(0)
		for _, value := range outer[i*16 : (i+1)*16] {
			limb = api.Add(api.Mul(256, limb), value.Val)
		}
		api.AssertIsEqual(limb, expected)
	}
	return nil
}

type nativeKey struct {
	Alpha [3]string    `json:"vk_alpha_1"`
	Beta  [3][2]string `json:"vk_beta_2"`
	Gamma [3][2]string `json:"vk_gamma_2"`
	Delta [3][2]string `json:"vk_delta_2"`
	IC    [3][3]string `json:"IC"`
}

type nativeProof struct {
	A [3]string    `json:"pi_a"`
	B [3][2]string `json:"pi_b"`
	C [3]string    `json:"pi_c"`
}

type fixture struct {
	Key              nativeKey `json:"inner_vk"`
	Context          string    `json:"context"`
	ContextStatement string    `json:"context_statement"`
	Parents          [2]struct {
		Proof     nativeProof `json:"proof"`
		Signals   [2]string   `json:"signals"`
		Statement string      `json:"statement"`
	} `json:"parents"`
}

func fpValue(text string) fp.Element {
	value, ok := new(big.Int).SetString(text, 10)
	if !ok || value.Sign() < 0 || value.Cmp(fp.Modulus()) >= 0 || value.String() != text {
		panic("noncanonical base-field coordinate in fixture")
	}
	return *new(fp.Element).SetBigInt(value)
}

func g1(raw [3]string) bls.G1Affine {
	if raw == [3]string{"0", "1", "0"} {
		return bls.G1Affine{}
	}
	if raw[2] != "1" {
		panic("expected affine G1 fixture point")
	}
	result := bls.G1Affine{X: fpValue(raw[0]), Y: fpValue(raw[1])}
	if !result.IsInSubGroup() {
		panic("fixture G1 point is outside its subgroup")
	}
	return result
}

func g2(raw [3][2]string) bls.G2Affine {
	if raw[2] != [2]string{"1", "0"} {
		panic("expected affine G2 fixture point")
	}
	var result bls.G2Affine
	result.X.A0, result.X.A1 = fpValue(raw[0][0]), fpValue(raw[0][1])
	result.Y.A0, result.Y.A1 = fpValue(raw[1][0]), fpValue(raw[1][1])
	if !result.IsInSubGroup() {
		panic("fixture G2 point is outside its subgroup")
	}
	return result
}

func doubleSHA(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

func digestLimbs(digest [32]byte) [2]frontend.Variable {
	return [2]frontend.Variable{new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:])}
}

func commitment(context []byte, statements [2][]byte) [2]frontend.Variable {
	preimage := append([]byte(outerDomain), context...)
	for _, statement := range statements {
		digest := doubleSHA(statement)
		preimage = append(preimage, digest[:]...)
	}
	return digestLimbs(doubleSHA(preimage))
}

func parseHex(encoded string, size int) []byte {
	b, err := hex.DecodeString(encoded)
	if err != nil || len(b) != size {
		panic("unexpected fixture data size or encoding")
	}
	return b
}

func assignment(fixture fixture, portableAsset bool) (aggregate, aggregate, [2][]byte, error) {
	var vk blsGroth16.VerifyingKey
	vk.G1.Alpha = g1(fixture.Key.Alpha)
	vk.G2.Beta = g2(fixture.Key.Beta)
	vk.G2.Gamma = g2(fixture.Key.Gamma)
	vk.G2.Delta = g2(fixture.Key.Delta)
	for _, point := range fixture.Key.IC {
		vk.G1.K = append(vk.G1.K, g1(point))
	}
	if err := vk.Precompute(); err != nil {
		return aggregate{}, aggregate{}, [2][]byte{}, err
	}
	fixedKey, err := recursive.ValueOfVerifyingKeyFixed[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](&vk)
	if err != nil {
		return aggregate{}, aggregate{}, [2][]byte{}, err
	}
	circuit := aggregate{key: fixedKey}
	context := parseHex(fixture.Context, 32)
	mimo := parseHex(fixture.ContextStatement, mimoSize)
	if digest := doubleSHA(mimo); string(digest[:]) != string(context) {
		return aggregate{}, aggregate{}, [2][]byte{}, fmt.Errorf("candidate context differs from statement hash")
	}
	var valid aggregate
	var statements [2][]byte
	if portableAsset {
		circuit.Asset = make([]frontend.Variable, assetSize)
		circuit.ChildTail = make([]frontend.Variable, mimoSize-assetEnd)
		valid.Asset = byteWitness(mimo[len(parentDomain):assetEnd])
		valid.ChildTail = byteWitness(mimo[assetEnd:])
	} else {
		circuit.Context = make([]frontend.Variable, 32)
		valid.Context = byteWitness(context)
	}
	for i, parent := range fixture.Parents {
		statements[i] = parseHex(parent.Statement, identitySize+bodySize)
		if string(statements[i][:len(parentDomain)]) != parentDomain {
			return aggregate{}, aggregate{}, [2][]byte{}, fmt.Errorf("parent %d uses a different statement version", i)
		}
		if i == 0 {
			copy(circuit.identity[:], statements[i])
			if portableAsset {
				clear(circuit.identity[len(parentDomain):assetEnd])
			}
		}
		for j, value := range statements[i][identitySize:] {
			valid.ParentBody[i][j] = value
		}
		proof := blsGroth16.Proof{Ar: g1(parent.Proof.A), Bs: g2(parent.Proof.B), Krs: g1(parent.Proof.C)}
		var nativeSignals fr.Vector = make([]fr.Element, 2)
		for j, limb := range digestLimbs(doubleSHA(statements[i])) {
			value := limb.(*big.Int)
			if value.String() != parent.Signals[j] {
				return aggregate{}, aggregate{}, [2][]byte{}, fmt.Errorf("parent %d signal %d differs from statement hash", i, j)
			}
			nativeSignals[j].SetBigInt(value)
		}
		if err := blsGroth16.Verify(&proof, &vk, nativeSignals); err != nil {
			return aggregate{}, aggregate{}, [2][]byte{}, fmt.Errorf("parent %d native verification: %w", i, err)
		}
		valid.Proofs[i], err = recursive.ValueOfProof[sw_bls12381.G1Affine, sw_bls12381.G2Affine](&proof)
		if err != nil {
			return aggregate{}, aggregate{}, [2][]byte{}, err
		}
	}
	valid.Digest = commitment(context, statements)
	return circuit, valid, statements, nil
}

func byteWitness(input []byte) []frontend.Variable {
	values := make([]frontend.Variable, len(input))
	for i, value := range input {
		values[i] = value
	}
	return values
}

func run(fixturePath string, prove, portableAsset bool, artifactPath, setupPath string) error {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		return err
	}
	var fixture fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return err
	}
	circuit, valid, statements, err := assignment(fixture, portableAsset)
	if err != nil {
		return err
	}
	field := ecc.BLS12_381.ScalarField()
	started := time.Now()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("outer compile: %s, %d R1CS constraints\n", time.Since(started), ccs.GetNbConstraints())
	for i, entry := range ccs.GetCommitments().(constraint.Groth16Commitments) {
		fmt.Printf("BSB22 commitment %d: public wire indexes %v\n", i, entry.GetPublicCommitted())
	}
	out, err := frontend.NewWitness(&valid, field)
	if err != nil {
		return err
	}
	started = time.Now()
	// The standalone solver has no proving key and cannot compute BSB22's
	// commitment. Exercise R1CS with a fresh test challenge, as the gnark test
	// harness does. Only Groth16.Prove below produces a verifiable commitment.
	solverChallenge := solver.OverrideHint(solver.GetHintID(frontendcs.Bsb22CommitmentComputePlaceholder),
		func(mod *big.Int, _ []*big.Int, output []*big.Int) error {
			x, err := rand.Int(rand.Reader, mod)
			if err != nil {
				return err
			}
			output[0].Set(x)
			return nil
		})
	if _, err := ccs.Solve(out, solverChallenge); err != nil {
		return fmt.Errorf("valid input solver: %w", err)
	}
	fmt.Printf("valid pair solved in %s\n", time.Since(started))
	wrongProof := valid
	wrongProof.Proofs[1] = valid.Proofs[0]
	wrongContext := valid
	if portableAsset {
		wrongContext.ChildTail = append([]frontend.Variable(nil), valid.ChildTail...)
		wrongContext.ChildTail[0] = valid.ChildTail[0].(uint8) ^ 1
	} else {
		wrongContext.Context = append([]frontend.Variable(nil), valid.Context...)
		wrongContext.Context[0] = valid.Context[0].(uint8) ^ 1
	}
	wrongStatement := valid
	changed := append([]byte(nil), statements[1]...)
	changed[identitySize] ^= 1 // Alter the parent preimage commitment.
	wrongStatement.ParentBody[1][0] = changed[identitySize]
	wrongStatement.Digest = commitment(parseHex(fixture.Context, 32), [2][]byte{statements[0], changed})
	duplicate := wrongProof
	duplicate.ParentBody[1] = valid.ParentBody[0]
	duplicate.Digest = commitment(parseHex(fixture.Context, 32), [2][]byte{statements[0], statements[0]})
	negativeCases := []struct {
		name  string
		input aggregate
	}{
		{"proof from a different parent", wrongProof},
		{"context switch under original public commitment", wrongContext},
		{"changed parent statement under new public commitment", wrongStatement},
		{"duplicate parent proof and statement", duplicate},
	}
	if portableAsset {
		foreignAsset := valid
		foreignAsset.Asset = append([]frontend.Variable(nil), valid.Asset...)
		foreignAsset.Asset[0] = valid.Asset[0].(uint8) ^ 1
		foreignChild := parseHex(fixture.ContextStatement, mimoSize)
		foreignChild[len(parentDomain)] ^= 1
		foreignContext := doubleSHA(foreignChild)
		foreignAsset.Digest = commitment(foreignContext[:], statements)
		negativeCases = append(negativeCases, struct {
			name  string
			input aggregate
		}{"one child asset and a different proven parent asset", foreignAsset})
	}
	for _, test := range negativeCases {
		negative, err := frontend.NewWitness(&test.input, field)
		if err != nil {
			return err
		}
		if _, err := ccs.Solve(negative, solverChallenge); err == nil {
			return fmt.Errorf("accepted %s", test.name)
		} else {
			var invalid *blsConstraint.UnsatisfiedConstraintError
			if !errors.As(err, &invalid) {
				return fmt.Errorf("unexpected solver failure for %s: %w", test.name, err)
			}
		}
		fmt.Printf("rejected %s\n", test.name)
	}
	if prove {
		started = time.Now()
		pk, outerVK, err := provingSetup(ccs, setupPath)
		if err != nil {
			return err
		}
		fmt.Printf("outer experiment setup/load: %s\n", time.Since(started))
		started = time.Now()
		outerProof, err := groth16.Prove(ccs, pk, out,
			recursive.GetNativeProverOptions(field, field))
		if err != nil {
			return err
		}
		fmt.Printf("outer Groth16 proof: %s\n", time.Since(started))
		public, err := out.Public()
		if err != nil {
			return err
		}
		started = time.Now()
		if err := groth16.Verify(outerProof, outerVK, public,
			recursive.GetNativeVerifierOptions(field, field)); err != nil {
			return err
		}
		proof, vk := outerProof.(*blsGroth16.Proof), outerVK.(*blsGroth16.VerifyingKey)
		fmt.Printf("outer verification: %s, %d commitment(s), %d VK IC points\n", time.Since(started),
			len(proof.Commitments), len(vk.G1.K))
		if artifactPath != "" {
			if err := exportOuterProof(artifactPath, vk, proof, valid.Digest); err != nil {
				return err
			}
		}
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fmt.Printf("Go heap reserved: %d MiB\n", stats.HeapSys/(1024*1024))
	return nil
}

func main() {
	prove := flag.Bool("prove", false, "run an ephemeral outer setup, generate a proof, and verify it")
	portableAsset := flag.Bool("portable-asset", false, "bind a shared asset witness to each parent and child statement")
	artifact := flag.String("artifact", "", "write the outer proof, verifying key and public inputs as experimental JSON")
	setup := flag.String("setup-dir", "", "save or load an experimental setup for this exact constraint system")
	flag.Parse()
	if flag.NArg() != 1 || ((*artifact != "" || *setup != "") && !*prove) {
		fmt.Fprintln(os.Stderr, "usage: recursion [-portable-asset] [-prove [-artifact proof.json] [-setup-dir parameters]] fixture.json")
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *prove, *portableAsset, *artifact, *setup); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

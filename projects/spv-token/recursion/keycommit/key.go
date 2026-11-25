// Package keycommit binds a witnessed BLS12-381 verifier key to a digest
// pinned by the asset's BSV verifier. It fixes the same two-public-input,
// one-commitment layout as the current BSB22 Script verifier.
package keycommit

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	recursion "github.com/consensys/gnark/std/recursion/groth16"
)

const domain = "BSV/CCTP/recursive-no-lines-vk/v1\x00"
const fieldBytes = 48

type Key = recursion.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]
type coordinate = emulated.Element[sw_bls12381.BaseField]

// Placeholder fixes all key dimensions at compile time.
func Placeholder() Key {
	var value Key
	value.G1.K = make([]sw_bls12381.G1Affine, 4)
	value.CommitmentKeys = make([]pedersen.VerifyingKey[sw_bls12381.G2Affine], 1)
	value.PublicAndCommitmentCommitted = [][]int{nil}
	return value
}

func coordinates(value *Key) ([]*coordinate, error) {
	if len(value.G1.K) != 4 || len(value.CommitmentKeys) != 1 ||
		len(value.PublicAndCommitmentCommitted) != 1 || len(value.PublicAndCommitmentCommitted[0]) != 0 {
		return nil, fmt.Errorf("expected two public inputs and one private BSB22 commitment")
	}
	extension := &value.E
	result := []*coordinate{
		&extension.A0, &extension.A1, &extension.A2, &extension.A3, &extension.A4, &extension.A5,
		&extension.A6, &extension.A7, &extension.A8, &extension.A9, &extension.A10, &extension.A11,
	}
	for i := range value.G1.K {
		point := &value.G1.K[i]
		result = append(result, &point.X, &point.Y)
	}
	for _, point := range []*sw_bls12381.G2Affine{
		&value.G2.GammaNeg, &value.G2.DeltaNeg, &value.CommitmentKeys[0].G, &value.CommitmentKeys[0].GSigmaNeg,
	} {
		if point.Lines != nil {
			return nil, fmt.Errorf("precomputed pairing lines are forbidden for witnessed keys")
		}
		result = append(result, &point.P.X.A0, &point.P.X.A1, &point.P.Y.A0, &point.P.Y.A1)
	}
	return result, nil
}

// Digest converts a native key to the exact pairing verifier representation
// that the circuit authenticates. The setup authority must pin this digest
// alongside a BSV Script verifier constructed from the same native key.
func Digest(nativeKey *native.VerifyingKey) ([32]byte, error) {
	var out [32]byte
	value, err := recursion.ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](nativeKey)
	if err != nil {
		return out, err
	}
	components, err := coordinates(&value)
	if err != nil {
		return out, err
	}
	field := ecc.BLS12_381.ScalarField()
	_, limbBits := emulated.GetEffectiveFieldParams[sw_bls12381.BaseField](field)
	encoded := make([]byte, len(domain)+fieldBytes*len(components))
	copy(encoded, domain)
	for i, component := range components {
		component.Initialize(field)
		number := new(big.Int)
		for j := len(component.Limbs) - 1; j >= 0; j-- {
			limb, ok := component.Limbs[j].(*big.Int)
			if !ok || limb.Sign() < 0 || uint(limb.BitLen()) > limbBits {
				return out, fmt.Errorf("unexpected native coordinate encoding")
			}
			number.Lsh(number, limbBits).Add(number, limb)
		}
		if number.Cmp(fp.Modulus()) >= 0 {
			return out, fmt.Errorf("native coordinate is outside the base field")
		}
		number.FillBytes(encoded[len(domain)+i*fieldBytes : len(domain)+(i+1)*fieldBytes])
	}
	first := sha256.Sum256(encoded)
	return sha256.Sum256(first[:]), nil
}

// Assert binds the actual fields used by gnark's dynamic pairing verifier.
// expected contains the same two ordered big-endian uint128 limbs used by
// the transaction statement. The circuit caller must tie them to a trusted
// key identity; extra witness limbs alone supply no authentication.
func Assert(api frontend.API, value *Key, expected [2]frontend.Variable) error {
	components, err := coordinates(value)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	bytes, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	message := uints.NewU8Array([]byte(domain))
	for _, component := range components {
		bits := field.ToBitsCanonical(component)
		for j := fieldBytes - 1; j >= 0; j-- {
			end := min(8*(j+1), len(bits))
			message = append(message, bytes.ValueOf(api.FromBinary(bits[8*j:end]...)))
		}
	}
	first, err := sha2.New(api)
	if err != nil {
		return err
	}
	first.Write(message)
	second, err := sha2.New(api)
	if err != nil {
		return err
	}
	second.Write(first.Sum())
	digest := second.Sum()
	for i, limb := range expected {
		value := frontend.Variable(0)
		for _, entry := range digest[16*i : 16*(i+1)] {
			value = api.Add(api.Mul(256, value), entry.Val)
		}
		api.AssertIsEqual(limb, value)
	}
	return nil
}

type Proof = recursion.Proof[sw_bls12381.G1Affine, sw_bls12381.G2Affine]

// AssertProof checks a BSB22 proof using a key authenticated by Assert.
// Inputs are an ordered pair of uint128 statement limbs. expected is the
// key commitment, and must be pinned by the caller's transaction relation.
func AssertProof(api frontend.API, key *Key, proof Proof, expected, inputs [2]frontend.Variable) error {
	if err := Assert(api, key, expected); err != nil {
		return err
	}
	scalar, err := emulated.NewField[sw_bls12381.ScalarField](api)
	if err != nil {
		return err
	}
	witness := recursion.Witness[sw_bls12381.ScalarField]{
		Public: make([]emulated.Element[sw_bls12381.ScalarField], len(inputs)),
	}
	for i, limb := range inputs {
		witness.Public[i] = *scalar.FromBits(api.ToBinary(limb, 128)...)
	}
	verifier, err := recursion.NewVerifier[sw_bls12381.ScalarField, sw_bls12381.G1Affine,
		sw_bls12381.G2Affine, sw_bls12381.GTEl](api)
	if err != nil {
		return err
	}
	return verifier.AssertProof(*key, proof, witness, recursion.WithSubgroupCheck(), recursion.WithCompleteArithmetic())
}

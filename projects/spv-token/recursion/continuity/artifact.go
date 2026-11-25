package main

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/keycommit"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

//go:embed padding.json
var paddingJSON []byte

type encodedG1 = [3]string
type encodedG2 = [3][2]string

type keyArtifact struct {
	Format     string       `json:"format"`
	Protocol   string       `json:"protocol"`
	Curve      string       `json:"curve"`
	Hash       string       `json:"hash_to_field"`
	Alpha      encodedG1    `json:"g1_alpha"`
	Beta       encodedG2    `json:"g2_beta"`
	Gamma      encodedG2    `json:"g2_gamma"`
	Delta      encodedG2    `json:"g2_delta"`
	IC         [4]encodedG1 `json:"ic"`
	Generator  encodedG2    `json:"commitment_g2"`
	SigmaNeg   encodedG2    `json:"commitment_g2_sigma_neg"`
	Indexes    []int        `json:"committed_public_indexes"`
	SelfDigest string       `json:"continuity_key_digest,omitempty"`
}

type proofArtifact struct {
	keyArtifact
	Signals    [2]string          `json:"public_signals"`
	ProofA     encodedG1          `json:"proof_a"`
	ProofB     encodedG2          `json:"proof_b"`
	ProofC     encodedG1          `json:"proof_c"`
	Commitment encodedG1          `json:"commitment"`
	Knowledge  encodedG1          `json:"commitment_knowledge_proof"`
	Statement  *statementArtifact `json:"continuity,omitempty"`
}

type statementArtifact struct {
	Asset   string    `json:"asset"`
	SelfKey string    `json:"self_key_digest"`
	Context string    `json:"transaction_context"`
	Count   uint8     `json:"count"`
	Prior   [2]string `json:"prior_digests"`
	Digest  string    `json:"digest"`
}

func encodeStatement(t Transcript) *statementArtifact {
	digest := t.Digest()
	return &statementArtifact{
		Asset: hex.EncodeToString(t.Asset[:]), SelfKey: hex.EncodeToString(t.SelfKey[:]),
		Context: hex.EncodeToString(t.Context[:]), Count: t.Count,
		Prior:  [2]string{hex.EncodeToString(t.Prior[0][:]), hex.EncodeToString(t.Prior[1][:])},
		Digest: hex.EncodeToString(digest[:]),
	}
}

func fieldElement(text string) (fp.Element, error) {
	n, ok := new(big.Int).SetString(text, 10)
	if !ok || n.Sign() < 0 || n.Cmp(fp.Modulus()) >= 0 || n.String() != text {
		return fp.Element{}, fmt.Errorf("noncanonical coordinate")
	}
	return *new(fp.Element).SetBigInt(n), nil
}

func readG1(point encodedG1) (bls.G1Affine, error) {
	var p bls.G1Affine
	if point == (encodedG1{"0", "1", "0"}) {
		return p, nil
	}
	if point[2] != "1" {
		return p, fmt.Errorf("invalid affine G1 point")
	}
	var err error
	p.X, err = fieldElement(point[0])
	if err != nil {
		return p, err
	}
	p.Y, err = fieldElement(point[1])
	if err != nil {
		return p, err
	}
	if !p.IsInSubGroup() {
		return p, fmt.Errorf("invalid G1 subgroup")
	}
	return p, nil
}

func readG2(point encodedG2) (bls.G2Affine, error) {
	var p bls.G2Affine
	if point[2] != [2]string{"1", "0"} {
		return p, fmt.Errorf("invalid affine G2 point")
	}
	values := []string{point[0][0], point[0][1], point[1][0], point[1][1]}
	for i, target := range []*fp.Element{&p.X.A0, &p.X.A1, &p.Y.A0, &p.Y.A1} {
		v, err := fieldElement(values[i])
		if err != nil {
			return p, err
		}
		*target = v
	}
	if !p.IsInSubGroup() {
		return p, fmt.Errorf("invalid G2 subgroup")
	}
	return p, nil
}

func (data keyArtifact) key() (*native.VerifyingKey, error) {
	if data.Format != "CCTP recursion experiment v1" || data.Curve != "bls12-381" ||
		data.Protocol != "gnark Groth16 BSB22" || data.Hash != "gnark NewShort BLS12-381 MiMC" ||
		data.Indexes == nil || len(data.Indexes) != 0 {
		return nil, fmt.Errorf("unsupported proof artifact format")
	}
	vk := &native.VerifyingKey{CommitmentKeys: make([]pedersen.VerifyingKey, 1), PublicAndCommitmentCommitted: [][]int{nil}}
	var err error
	vk.G1.Alpha, err = readG1(data.Alpha)
	if err != nil {
		return nil, err
	}
	for i, target := range []*bls.G2Affine{&vk.G2.Beta, &vk.G2.Gamma, &vk.G2.Delta, &vk.CommitmentKeys[0].G, &vk.CommitmentKeys[0].GSigmaNeg} {
		v, err := readG2([]encodedG2{data.Beta, data.Gamma, data.Delta, data.Generator, data.SigmaNeg}[i])
		if err != nil {
			return nil, err
		}
		*target = v
	}
	for _, raw := range data.IC {
		p, err := readG1(raw)
		if err != nil {
			return nil, err
		}
		vk.G1.K = append(vk.G1.K, p)
	}
	return vk, vk.Precompute()
}

func (data proofArtifact) proof() (*native.Proof, [32]byte, error) {
	p := &native.Proof{Commitments: make([]bls.G1Affine, 1)}
	var digest [32]byte
	for i, coord := range data.Signals {
		v, ok := new(big.Int).SetString(coord, 10)
		if !ok || v.Sign() < 0 || v.BitLen() > 128 || coord != v.String() {
			return nil, digest, fmt.Errorf("noncanonical public limb %d", i)
		}
		v.FillBytes(digest[16*i : 16*(i+1)])
	}
	var err error
	p.Bs, err = readG2(data.ProofB)
	if err != nil {
		return nil, digest, err
	}
	for i, target := range []*bls.G1Affine{&p.Ar, &p.Krs, &p.Commitments[0], &p.CommitmentPok} {
		v, err := readG1([]encodedG1{data.ProofA, data.ProofC, data.Commitment, data.Knowledge}[i])
		if err != nil {
			return nil, digest, err
		}
		*target = v
	}
	return p, digest, nil
}

func nativeVerify(vk *native.VerifyingKey, proof *native.Proof, digest [32]byte) error {
	input := make(fr.Vector, 2)
	for i, limb := range limbs(digest) {
		input[i].SetBigInt(limb)
	}
	field := fr.Modulus()
	return native.Verify(proof, vk, input, recursive.GetNativeVerifierOptions(field, field))
}

func loadPadding() (padding, *native.VerifyingKey, error) {
	var art proofArtifact
	if err := json.Unmarshal(paddingJSON, &art); err != nil {
		return padding{}, nil, err
	}
	vk, err := art.key()
	if err != nil {
		return padding{}, nil, err
	}
	proof, digest, err := art.proof()
	if err != nil {
		return padding{}, nil, err
	}
	if err := nativeVerify(vk, proof, digest); err != nil {
		return padding{}, nil, err
	}
	key, err := recursive.ValueOfVerifyingKey[G1, G2, GT](vk)
	if err != nil {
		return padding{}, nil, err
	}
	p, err := recursive.ValueOfProof[G1, G2](proof)
	return padding{key, p, limbs(digest)}, vk, err
}

func encodedPoint(p bls.G1Affine) encodedG1 {
	if p.IsInfinity() {
		return encodedG1{"0", "1", "0"}
	}
	return encodedG1{p.X.String(), p.Y.String(), "1"}
}

func encodedTwist(p bls.G2Affine) encodedG2 {
	return encodedG2{{p.X.A0.String(), p.X.A1.String()}, {p.Y.A0.String(), p.Y.A1.String()}, {"1", "0"}}
}

func encodeKey(vk *native.VerifyingKey) (keyArtifact, error) {
	digest, err := keycommit.Digest(vk)
	if err != nil {
		return keyArtifact{}, err
	}
	return keyArtifact{
		Format: "CCTP recursion experiment v1", Protocol: "gnark Groth16 BSB22", Curve: "bls12-381", Hash: "gnark NewShort BLS12-381 MiMC",
		Alpha: encodedPoint(vk.G1.Alpha), Beta: encodedTwist(vk.G2.Beta), Gamma: encodedTwist(vk.G2.Gamma), Delta: encodedTwist(vk.G2.Delta),
		IC:        [4]encodedG1{encodedPoint(vk.G1.K[0]), encodedPoint(vk.G1.K[1]), encodedPoint(vk.G1.K[2]), encodedPoint(vk.G1.K[3])},
		Generator: encodedTwist(vk.CommitmentKeys[0].G), SigmaNeg: encodedTwist(vk.CommitmentKeys[0].GSigmaNeg),
		Indexes: []int{}, SelfDigest: hex.EncodeToString(digest[:]),
	}, nil
}

func encodeProof(key keyArtifact, proof *native.Proof, transcript Transcript) proofArtifact {
	inputs := limbs(transcript.Digest())
	return proofArtifact{keyArtifact: key, Signals: [2]string{inputs[0].String(), inputs[1].String()},
		ProofA: encodedPoint(proof.Ar), ProofB: encodedTwist(proof.Bs), ProofC: encodedPoint(proof.Krs),
		Commitment: encodedPoint(proof.Commitments[0]), Knowledge: encodedPoint(proof.CommitmentPok), Statement: encodeStatement(transcript)}
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0600)
}

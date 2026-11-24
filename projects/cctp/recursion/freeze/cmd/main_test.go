package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/conservation"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/parentcheckpoint"
)

func TestStatementsAndProofArtifacts(t *testing.T) {
	raw, err := os.ReadFile("../testdata/script-control.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Statement string `json:"statement"`
		Digest    string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	_, _, g1, g2 := bls.Generators()
	for _, profile := range []string{plainProfile, bsb22Profile} {
		t.Run(profile, func(t *testing.T) {
			m := manifest{Profile: profile, TestOnly: true}
			vk, proof := new(native.VerifyingKey), new(native.Proof)
			vk.G1.Alpha, vk.G1.K = g1, []bls.G1Affine{g1, g1, g1}
			vk.G2.Beta, vk.G2.Gamma, vk.G2.Delta = g2, g2, g2
			proof.Ar, proof.Bs, proof.Krs = g1, g2, g1
			if profile == bsb22Profile {
				m.Commitments = 1
				vk.G1.K = append(vk.G1.K, g1)
				vk.CommitmentKeys = []pedersen.VerifyingKey{{G: g2, GSigmaNeg: g2}}
				vk.PublicAndCommitmentCommitted = [][]int{nil}
				proof.Commitments, proof.CommitmentPok = []bls.G1Affine{g1}, g1
			}
			for _, vector := range vectors {
				statement, err := parseStatement(vector.Statement)
				if err != nil {
					t.Fatal(err)
				}
				artifact, err := keyArtifact(m, vk)
				if err != nil {
					t.Fatal(err)
				}
				if err := addProof(artifact, profile, proof, statement); err != nil {
					t.Fatal(err)
				}
				if artifact["statement"] != vector.Statement || artifact["statement_digest"] != vector.Digest {
					t.Fatal("artifact changes the supplied canonical statement or its digest")
				}
				limbs := statement.Limbs()
				if artifact["public_signals"] != ([2]string{limbs[0].String(), limbs[1].String()}) {
					t.Fatal("artifact has the wrong big-endian limbs")
				}
			}
		})
	}
	for _, wire := range []string{"", vectors[0].Statement[2:], "00" + vectors[0].Statement[2:], "xx" + vectors[0].Statement[2:]} {
		if _, err := parseStatement(wire); err == nil {
			t.Fatal("accepted malformed freeze statement")
		}
	}
}

func TestNativeFileFingerprintAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setup.key")
	expected := []byte("freeze test artifact")
	digest, err := writeNative(path, bytes.NewReader(expected))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeNative(path, bytes.NewReader([]byte("replacement"))); err == nil {
		t.Fatal("existing setup artifact was overwritten")
	}
	var result bytes.Buffer
	if err := readNative(path, digest, &result); err != nil || !bytes.Equal(expected, result.Bytes()) {
		t.Fatalf("round-trip of fingerprinted setup file failed: %v", err)
	}
	if err := readNative(path, hex.EncodeToString(make([]byte, 32)), &result); err == nil {
		t.Fatal("accepted an incorrect setup-file fingerprint")
	}
}

func TestProfileConstraintFingerprints(t *testing.T) {
	fingerprints := make(map[string]string)
	for _, profile := range []string{plainProfile, bsb22Profile, conservationProfile, parentCheckpointProfile} {
		var fingerprint string
		for repeat := 0; repeat < 2; repeat++ {
			_, m, err := compileFreeze(profile)
			if err != nil {
				t.Fatal(err)
			}
			if repeat > 0 && fingerprint != m.CircuitSHA256 {
				t.Fatalf("%s has unstable circuit serialization", profile)
			}
			fingerprint = m.CircuitSHA256
			t.Logf("%s: %d constraints, %d commitments, %s", profile, m.Constraints, m.Commitments, m.CircuitSHA256)
		}
		if other, exists := fingerprints[fingerprint]; exists {
			t.Fatalf("%s and %s share a circuit fingerprint", profile, other)
		}
		fingerprints[fingerprint] = profile
	}
}

func TestConservationProfileStatementAndArtifact(t *testing.T) {
	wire := hex.EncodeToString((conservation.Statement{}).Encode())
	statement, assignment, err := assignmentFor(conservationProfile, wire, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := assignment.(*conservation.Circuit); !ok {
		t.Fatal("wrong circuit assignment for conservation profile")
	}
	if _, _, err := assignmentFor(plainProfile, wire, ""); err == nil {
		t.Fatal("freeze profile accepted a conservation statement")
	}

	_, _, g1, g2 := bls.Generators()
	vk, proof := new(native.VerifyingKey), new(native.Proof)
	vk.G1.Alpha, vk.G1.K = g1, []bls.G1Affine{g1, g1, g1}
	vk.G2.Beta, vk.G2.Gamma, vk.G2.Delta = g2, g2, g2
	proof.Ar, proof.Bs, proof.Krs = g1, g2, g1
	key, err := keyArtifact(manifest{Profile: conservationProfile, TestOnly: true}, vk)
	if err != nil {
		t.Fatal(err)
	}
	if err := addProof(key, conservationProfile, proof, statement); err != nil {
		t.Fatal(err)
	}
	if key["format"] != "CCTP conservation Groth16 artifact v1" || key["statement"] != wire || key["freeze_profile"] != nil {
		t.Fatal("incorrect conservation artifact profile")
	}
}

func TestParentCheckpointProfileAssignment(t *testing.T) {
	wire := hex.EncodeToString((parentcheckpoint.Statement{}).Encode())
	raw := hex.EncodeToString(make([]byte, parentcheckpoint.ParentSize))
	statement, assignment, err := assignmentFor(parentCheckpointProfile, wire, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := assignment.(*parentcheckpoint.Circuit); !ok || hex.EncodeToString(statement.Encode()) != wire {
		t.Fatal("wrong circuit assignment for parent checkpoint profile")
	}
	for _, malformed := range []string{"", raw[2:], raw + "00", "xx" + raw[2:]} {
		if _, _, err := assignmentFor(parentCheckpointProfile, wire, malformed); err == nil {
			t.Fatal("accepted a malformed parent transaction input")
		}
	}
	if _, _, err := assignmentFor(conservationProfile, wire, raw); err == nil {
		t.Fatal("conservation profile accepted parent checkpoint input")
	}
	tokenRaw := hex.EncodeToString(make([]byte, parentcheckpoint.TokenParentSize))
	statement, assignment, err = assignmentFor(tokenCheckpointProfile, wire, tokenRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := assignment.(*parentcheckpoint.TokenCircuit); !ok || hex.EncodeToString(statement.Encode()) != wire {
		t.Fatal("wrong circuit assignment for token parent checkpoint profile")
	}
	if _, _, err := assignmentFor(tokenCheckpointProfile, wire, raw); err == nil {
		t.Fatal("token parent checkpoint accepted the shorter profile's input")
	}
	if _, _, err := assignmentFor(parentCheckpointProfile, wire, tokenRaw); err == nil {
		t.Fatal("short parent checkpoint accepted the token profile's input")
	}
}

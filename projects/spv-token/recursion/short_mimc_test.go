package main

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/consensys/gnark/std/recursion"
)

func TestShortMiMCVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/short-mimc.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Point     [2]string `json:"point"`
		Challenge string    `json:"challenge"`
		Constants []string  `json:"round_constants"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var point bls.G1Affine
	point.ScalarMultiplicationBase(big.NewInt(27))
	if vector.Point != [2]string{point.X.String(), point.Y.String()} {
		t.Fatal("commitment coordinates do not match")
	}
	constants := mimc.GetConstants()
	if len(constants) != len(vector.Constants) {
		t.Fatal("unexpected number of round constants")
	}
	for i, constant := range constants {
		if constant.Text(16) != vector.Constants[i] {
			t.Fatalf("wrong constant %d", i)
		}
	}
	transcript, err := recursion.NewShort(fr.Modulus(), fr.Modulus())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transcript.Write(point.Marshal()); err != nil {
		t.Fatal(err)
	}
	if got := new(big.Int).SetBytes(transcript.Sum(nil)).String(); got != vector.Challenge {
		t.Fatalf("wrong challenge %s", got)
	}
}

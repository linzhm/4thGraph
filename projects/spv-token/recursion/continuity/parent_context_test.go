package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/parentcheckpoint"
)

// These wire transactions and public digests were generated with the Python
// transaction, OTDA and ParentReceipt encoders. Their small lock scripts
// isolate the parent relation from issuance rules.
const mintParentWire = "0200000002313131313131313131313131313131313131313131313131313131313131313100000000020151ffffffff9191919191919191919191919191919191919191919191919191919191919191040000000c5151515151515151515151516100008004dc050000000000000a6d696e742d7374617465e80300000000000009746f6b656e2d6f6e650000000000000000056576656e74000000000000000064006a1f4253562f434354502f636f6e74696e756974792d706172656e74732f76310041000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000"
const transferParentWire = "02000000039292929292929292929292929292929292929292929292929292929292929292050000000c515151515151515151515151610000800df4109c4e278ff3d1dca75dfbb5bb3faab9da2e34fe9750b161a829bdbeae9e01000000020151ffffffffa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10800000003025151ffffffff03e80300000000000009746f6b656e2d6f6e65e80300000000000009746f6b656e2d6f6e65000000000000000064006a1f4253562f434354502f636f6e74696e756974792d706172656e74732f76310041026363636363636363636363636363636363636363636363636363636363636363747474747474747474747474747474747474747474747474747474747474747406000000"
const mintParentDigest = "656756ef7b7a4fc2650d84e63a068fc5537fe27d462670ed29e835a63db6d0ee"
const transferParentDigest = "6a3f2d3f5e9cd2d4b3d12dd331c78d0a5c2a1383c9113636b198a2b783a6fcae"
const compactChronicleScriptCode = "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"

type parentContextFixture struct {
	Outpoint [36]frontend.Variable `gnark:",public"`
	Digest   [32]frontend.Variable `gnark:",public"`
	Approved [2][36]frontend.Variable
	Raw      [295]frontend.Variable
	Layout   frontend.Variable
}

func (c *parentContextFixture) Define(api frontend.API) error {
	var asset, selfKey [32]frontend.Variable
	for i := range asset {
		asset[i], selfKey[i] = i, i+32
	}
	digest, err := c.deriveDigest(api, asset, selfKey)
	if err != nil {
		return err
	}
	for i, value := range c.Digest {
		api.AssertIsEqual(digest[i], value)
	}
	return nil
}

func (c *parentContextFixture) deriveDigest(api frontend.API, asset, selfKey [32]frontend.Variable) ([32]frontend.Variable, error) {
	var selected [32]frontend.Variable
	profiles := []parentcheckpoint.ParentOutputLayout{
		{
			Layout: parentcheckpoint.FixedParentLayout{
				InputScriptLengths: []int{2, 12}, OutputScriptLengths: []int{10, 9, 5, 100},
			},
			EligibleVouts: []int{1},
		},
		{
			Layout: parentcheckpoint.FixedParentLayout{
				InputScriptLengths: []int{12, 2, 3}, OutputScriptLengths: []int{9, 9, 100},
			},
			EligibleVouts: []int{0, 1},
		},
	}
	parent, err := parentcheckpoint.BindParentOutput(api, c.Raw[:], c.Outpoint[:], c.Layout, profiles)
	if err != nil {
		return selected, err
	}
	code, err := hex.DecodeString(compactChronicleScriptCode)
	if err != nil {
		return selected, err
	}
	chronicleProfiles := []chronicleParentProfile{
		{VerifierVin: 1, ScriptCode: code, MinParents: 0, MaxParents: 1},
		{VerifierVin: 0, ScriptCode: code, MinParents: 2, MaxParents: 2},
	}
	selected, err = chronicleParentDigest(api, parent.Layouts, chronicleProfiles, asset, selfKey, c.Approved[:])
	if err != nil {
		return selected, err
	}
	api.AssertIsEqual(parent.Satoshis, 1000)
	return selected, nil
}

func contextFixtureBytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func parentContextAssignment(t *testing.T, raw []byte, digest [32]byte, layout, vout byte) parentContextFixture {
	t.Helper()
	var out parentContextFixture
	out.Layout = layout
	for i := range out.Raw {
		out.Raw[i] = 0
	}
	for i, value := range raw {
		out.Raw[i] = value
	}
	first := sha256.Sum256(raw)
	for i, value := range sha256.Sum256(first[:]) {
		out.Outpoint[i] = value
	}
	out.Outpoint[32], out.Outpoint[33], out.Outpoint[34], out.Outpoint[35] = vout, 0, 0, 0
	for i, value := range digest {
		out.Digest[i] = value
	}
	for i := 0; i < 32; i++ {
		out.Approved[0][i], out.Approved[1][i] = 0x91, 0x92
	}
	out.Approved[0][32], out.Approved[1][32] = 4, 5
	for i := 33; i < 36; i++ {
		out.Approved[0][i], out.Approved[1][i] = 0, 0
	}
	return out
}

func TestChronicleParentStatementUsesTheSelectedLayout(t *testing.T) {
	field := fr.Modulus()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, &parentContextFixture{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mixed-shape parent opening and predecessor digest: %d constraints", ccs.GetNbConstraints())
	assignment := func(raw []byte, digest string, layout, vout byte) parentContextFixture {
		return parentContextAssignment(t, raw, [32]byte(contextFixtureBytes(t, digest)), layout, vout)
	}
	solve := func(t *testing.T, candidate parentContextFixture, accept bool) {
		t.Helper()
		witness, err := frontend.NewWitness(&candidate, field)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ccs.Solve(witness); (err == nil) != accept {
			t.Fatalf("expected accept=%t, solver returned %v", accept, err)
		}
	}

	mint := contextFixtureBytes(t, mintParentWire)
	transfer := contextFixtureBytes(t, transferParentWire)
	validMint := assignment(mint, mintParentDigest, 0, 1)
	solve(t, validMint, true)
	solve(t, assignment(transfer, transferParentDigest, 1, 0), true)
	solve(t, assignment(transfer, transferParentDigest, 1, 1), true)
	solve(t, assignment(mint, transferParentDigest, 0, 1), false)
	solve(t, assignment(mint, mintParentDigest, 0, 0), false)
	unapproved := validMint
	unapproved.Approved[0][32] = 5
	solve(t, unapproved, false)

	// The amended txid and digest match each malformed transaction so that
	// canonical receipt and sequence checks cause the rejection.
	for _, negative := range []struct {
		name   string
		offset int
		value  byte
		digest string
	}{
		{"wrong receipt prefix", 162, 0x51, "b0222b274443ce954ad133a315f4d731eaf887a4b7e2b927e0f2fe1651bdba67"},
		{"nonzero receipt padding", 261, 1, "5e5d29626e193da2183916cc1f94933fd169eac2e0921b4425c9b1c64f9b52e0"},
		{"wrong sighash sequence", 97, 0x41, "69ddda09cb32b06f385aa247d0c6ac9c86a2bb1752d01474167263a5ae508e5d"},
	} {
		t.Run(negative.name, func(t *testing.T) {
			bad := append([]byte{}, mint...)
			bad[negative.offset] = negative.value
			solve(t, assignment(bad, negative.digest, 0, 1), false)
		})
	}
}

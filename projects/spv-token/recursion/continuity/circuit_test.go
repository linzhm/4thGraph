package main

import (
	"encoding/hex"
	"testing"
)

func TestContinuityWireVector(t *testing.T) {
	var transcript Transcript
	transcript.Count = 2
	for i := range transcript.Asset {
		transcript.Asset[i] = byte(i)
		transcript.SelfKey[i] = byte(32 + i)
		transcript.Context[i] = byte(64 + i)
		transcript.Prior[0][i] = byte(96 + i)
		transcript.Prior[1][i] = byte(128 + i)
	}
	digest := transcript.Digest()
	if got := hex.EncodeToString(digest[:]); got != "9fef2619631d43e4da8c807b1fbc92a00f35f20a2e4c7dcf2ab60493d1160d0a" {
		t.Fatalf("wrong continuity wire digest %s", got)
	}
	reverse := transcript
	reverse.Prior[0], reverse.Prior[1] = reverse.Prior[1], reverse.Prior[0]
	if reverse.Digest() == digest {
		t.Fatal("predecessor order was lost")
	}
	public := limbs(digest)
	var roundtrip [32]byte
	public[0].FillBytes(roundtrip[:16])
	public[1].FillBytes(roundtrip[16:])
	if roundtrip != digest {
		t.Fatal("public inputs must be ordered big-endian uint128 limbs")
	}
}

func TestEmbeddedPaddingArtifact(t *testing.T) {
	_, vk, err := loadPadding()
	if err != nil {
		t.Fatal(err)
	}
	art, err := encodeKey(vk)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := art.key()
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeKey(restored)
	if err != nil {
		t.Fatal(err)
	}
	if art.SelfDigest != again.SelfDigest {
		t.Fatal("native key JSON changed its continuity identifier")
	}
}
